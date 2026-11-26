//! RFC 4978 `COMPRESS=DEFLATE` async stream wrapper using raw RFC 1951 DEFLATE (`flate2`),
//! sync-flushing every response write and enforcing strict decompression DoS limits.

use std::{
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Fixed per-call output chunk size for raw RFC 1951 inflation (16 KiB).
const INFLATE_CHUNK_BYTES: usize = 16 * 1024;
/// Maximum buffered unread compressed input bytes retained between inflate steps.
const MAX_COMPRESSED_BUFFER_BYTES: usize = 256 * 1024;
/// Default grace threshold before enforcing the compression ratio cap (64 KiB).
pub const DEFAULT_DEFLATE_RATIO_GRACE_BYTES: u64 = 64 * 1024;
/// Default maximum allowed decompressed-to-compressed expansion ratio (100:1).
pub const DEFAULT_DEFLATE_MAX_EXPANSION_RATIO: u64 = 100;
/// Minimum absolute connection-lifetime decompressed byte ceiling (64 MiB).
pub const MIN_DEFLATE_MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// DoS protection limits enforced on incoming DEFLATE-compressed IMAP client bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateLimits {
    /// Absolute cap on cumulative decompressed bytes accepted over one connection.
    pub max_decompressed_bytes: u64,
    /// Grace threshold in decompressed bytes before enforcing `max_expansion_ratio`.
    pub ratio_grace_bytes: u64,
    /// Maximum allowed `total_decompressed / total_compressed` ratio once past `ratio_grace_bytes`.
    pub max_expansion_ratio: u64,
}

impl DeflateLimits {
    /// Compute sensible defaults scaled from the server's configured `max_body_bytes`.
    pub fn for_max_body_bytes(max_body_bytes: usize) -> Self {
        let scaled = (max_body_bytes as u64).saturating_mul(8);
        Self {
            max_decompressed_bytes: scaled.max(MIN_DEFLATE_MAX_DECOMPRESSED_BYTES),
            ratio_grace_bytes: DEFAULT_DEFLATE_RATIO_GRACE_BYTES,
            max_expansion_ratio: DEFAULT_DEFLATE_MAX_EXPANSION_RATIO,
        }
    }
}

/// Async stream implementing RFC 4978 `COMPRESS=DEFLATE` over an arbitrary underlying transport.
pub struct DeflateImapStream<T> {
    inner: T,
    compress: Compress,
    decompress: Decompress,
    limits: DeflateLimits,
    /// Compressed bytes waiting to be written to `inner`.
    write_buf: Vec<u8>,
    write_pos: usize,
    need_sync_flush: bool,
    /// Compressed bytes read from `inner` waiting to be inflated.
    comp_buf: Vec<u8>,
    comp_pos: usize,
    /// Inflated bytes waiting to be returned to `poll_read`.
    decomp_buf: Vec<u8>,
    decomp_pos: usize,
    read_eof: bool,
}

impl<T> DeflateImapStream<T> {
    /// Wrap `inner` in raw RFC 1951 DEFLATE compression/decompression, seeding the inflate buffer
    /// with any already-buffered compressed bytes left in a `BufReader` after `COMPRESS DEFLATE`.
    pub fn new(inner: T, initial_compressed: Vec<u8>, limits: DeflateLimits) -> Self {
        Self {
            inner,
            compress: Compress::new(Compression::default(), false),
            decompress: Decompress::new(false),
            limits,
            write_buf: Vec::new(),
            write_pos: 0,
            need_sync_flush: false,
            comp_buf: initial_compressed,
            comp_pos: 0,
            decomp_buf: Vec::new(),
            decomp_pos: 0,
            read_eof: false,
        }
    }

    /// Borrow the underlying transport stream.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    fn check_decompression_limits(&self) -> io::Result<()> {
        let total_out = self.decompress.total_out();
        if total_out > self.limits.max_decompressed_bytes {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "IMAP DEFLATE decompressed byte limit ({}) exceeded",
                    self.limits.max_decompressed_bytes
                ),
            ));
        }
        let total_in = self.decompress.total_in().max(1);
        if total_out > self.limits.ratio_grace_bytes
            && total_out > total_in.saturating_mul(self.limits.max_expansion_ratio)
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "IMAP DEFLATE decompression ratio limit ({}:1) exceeded",
                    self.limits.max_expansion_ratio
                ),
            ));
        }
        Ok(())
    }

    fn drain_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "IMAP DEFLATE inner stream returned 0 bytes written",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_pos += n;
                }
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn emit_sync_flush(&mut self) -> io::Result<()> {
        if !self.need_sync_flush {
            return Ok(());
        }
        loop {
            self.write_buf.reserve(512);
            let before_out = self.compress.total_out();
            let cap = self.write_buf.capacity();
            let status = self
                .compress
                .compress_vec(&[], &mut self.write_buf, FlushCompress::Sync)
                .map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("IMAP DEFLATE sync flush error: {e}"),
                    )
                })?;
            let produced = (self.compress.total_out() - before_out) as usize;
            if status == Status::StreamEnd
                || (self.write_buf.len() < cap && (status == Status::Ok || produced == 0))
            {
                break;
            }
        }
        self.need_sync_flush = false;
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for DeflateImapStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.decomp_pos < this.decomp_buf.len() {
            let avail = &this.decomp_buf[this.decomp_pos..];
            let take = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..take]);
            this.decomp_pos += take;
            if this.decomp_pos >= this.decomp_buf.len() {
                this.decomp_buf.clear();
                this.decomp_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let mut scratch = [0u8; INFLATE_CHUNK_BYTES];
        loop {
            if this.comp_pos < this.comp_buf.len() {
                let before_in = this.decompress.total_in();
                let before_out = this.decompress.total_out();
                let status = this
                    .decompress
                    .decompress(
                        &this.comp_buf[this.comp_pos..],
                        &mut scratch,
                        FlushDecompress::Sync,
                    )
                    .map_err(|e| {
                        io::Error::new(
                            ErrorKind::InvalidData,
                            format!("IMAP DEFLATE decompression error: {e}"),
                        )
                    })?;
                let consumed = (this.decompress.total_in() - before_in) as usize;
                let produced = (this.decompress.total_out() - before_out) as usize;
                this.comp_pos += consumed;
                if this.comp_pos >= this.comp_buf.len() {
                    this.comp_buf.clear();
                    this.comp_pos = 0;
                }

                this.check_decompression_limits()?;

                if produced > 0 {
                    let take = produced.min(buf.remaining());
                    buf.put_slice(&scratch[..take]);
                    if take < produced {
                        this.decomp_buf.clear();
                        this.decomp_pos = 0;
                        this.decomp_buf.extend_from_slice(&scratch[take..produced]);
                    }
                    return Poll::Ready(Ok(()));
                }

                if status == Status::StreamEnd {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }

                if consumed > 0 {
                    // Consumed compressed metadata/padding; try inflating remaining bytes.
                    continue;
                }
            }

            if this.read_eof {
                return Poll::Ready(Ok(()));
            }

            if this.comp_pos > 0 {
                this.comp_buf.drain(..this.comp_pos);
                this.comp_pos = 0;
            }
            if this.comp_buf.len() >= MAX_COMPRESSED_BUFFER_BYTES {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "IMAP DEFLATE compressed input buffer exceeded limit",
                )));
            }

            let mut read_tmp = [0u8; 8192];
            let mut rbuf = ReadBuf::new(&mut read_tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.comp_buf.extend_from_slice(filled);
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DeflateImapStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.drain_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut consumed = 0usize;
        while consumed < buf.len() {
            let before_in = this.compress.total_in();
            this.write_buf
                .reserve((buf.len() - consumed).clamp(256, 16 * 1024) + 64);
            let status = this
                .compress
                .compress_vec(&buf[consumed..], &mut this.write_buf, FlushCompress::None)
                .map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("IMAP DEFLATE compression error: {e}"),
                    )
                })?;
            let delta_in = (this.compress.total_in() - before_in) as usize;
            consumed += delta_in;
            if status == Status::StreamEnd {
                break;
            }
            if delta_in == 0 && this.write_buf.len() < this.write_buf.capacity() {
                break;
            }
        }
        this.need_sync_flush = true;
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.emit_sync_flush()?;
        match this.drain_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.emit_sync_flush()?;
        match this.drain_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn deflate_stream_round_trips_messages_with_sync_flush() {
        let (a, b) = tokio::io::duplex(4096);
        let limits = DeflateLimits::for_max_body_bytes(1024 * 1024);
        let mut client = DeflateImapStream::new(a, Vec::new(), limits);
        let mut server = DeflateImapStream::new(b, Vec::new(), limits);

        client.write_all(b"A1 NOOP\r\n").await.unwrap();
        client.flush().await.unwrap();

        let mut buf = [0u8; 32];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"A1 NOOP\r\n");

        server.write_all(b"A1 OK NOOP completed\r\n").await.unwrap();
        server.flush().await.unwrap();

        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"A1 OK NOOP completed\r\n");
    }

    #[tokio::test]
    async fn deflate_stream_rejects_zip_bomb_ratio_and_byte_cap() {
        // Compress 512 KiB of repeated 'A' bytes (~520 bytes compressed -> ~1000:1 ratio).
        let bomb_plain = vec![b'A'; 512 * 1024];
        let mut comp = Compress::new(Compression::best(), false);
        let mut bomb_compressed = Vec::new();
        let mut offset = 0usize;
        while offset < bomb_plain.len() {
            let before = comp.total_in();
            bomb_compressed.reserve(1024);
            comp.compress_vec(
                &bomb_plain[offset..],
                &mut bomb_compressed,
                FlushCompress::None,
            )
            .unwrap();
            offset += (comp.total_in() - before) as usize;
        }
        bomb_compressed.reserve(1024);
        comp.compress_vec(&[], &mut bomb_compressed, FlushCompress::Sync)
            .unwrap();
        assert!(bomb_compressed.len() < 2048);

        let (mut writer, reader) = tokio::io::duplex(4096);
        let limits = DeflateLimits {
            max_decompressed_bytes: 16 * 1024 * 1024,
            ratio_grace_bytes: 64 * 1024,
            max_expansion_ratio: 100,
        };
        let mut server = DeflateImapStream::new(reader, Vec::new(), limits);

        let write_task = tokio::spawn(async move {
            let _ = writer.write_all(&bomb_compressed).await;
            let _ = writer.flush().await;
        });

        let mut out = Vec::new();
        let err = server.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("ratio limit"));
        let _ = write_task.await;
    }

    #[tokio::test]
    async fn deflate_stream_enforces_absolute_decompressed_byte_cap() {
        // Pseudo-random incompressible-ish data compressed with low ratio, hitting max_decompressed_bytes.
        let payload: Vec<u8> = (0..4096u32)
            .map(|i| ((i.wrapping_mul(2654435761) >> 24) & 0xff) as u8)
            .collect();
        let mut comp = Compress::new(Compression::default(), false);
        let mut compressed = Vec::with_capacity(payload.len() + 64);
        comp.compress_vec(&payload, &mut compressed, FlushCompress::Sync)
            .unwrap();

        let (mut writer, reader) = tokio::io::duplex(8192);
        let limits = DeflateLimits {
            max_decompressed_bytes: 2048,
            ratio_grace_bytes: 64 * 1024,
            max_expansion_ratio: 100,
        };
        let mut server = DeflateImapStream::new(reader, Vec::new(), limits);
        writer.write_all(&compressed).await.unwrap();
        drop(writer);

        let mut out = Vec::new();
        let err = server.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("byte limit"));
    }
}
