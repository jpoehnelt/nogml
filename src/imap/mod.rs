//! Embedded IMAP4rev1 server (plain TCP + optional STARTTLS + optional implicit TLS),
//! supporting RFC 3501/2177/6851/6154/7888/4959 commands, Gmail virtual folders,
//! flags <-> labels mapping, and real-time `IDLE` via `AppState::events`.
//!
//! Owned by the `imap-sync` worker.

pub mod mime_fmt;
pub mod parser;
pub mod session;
#[cfg(test)]
pub(crate) mod tests;

use std::{path::Path, sync::Arc};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::{
    AppState, ensure_crypto_provider,
    error::{AppError, AppResult},
    imap::session::{ImapStream, handle_connection},
};

/// Load a [`TlsAcceptor`] from PEM certificate chain and private key paths.
pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> AppResult<TlsAcceptor> {
    ensure_crypto_provider();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| AppError::Config(format!("Failed to open IMAP TLS cert {cert_path:?}: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            AppError::Config(format!("Failed to parse IMAP TLS cert {cert_path:?}: {e}"))
        })?;
    if certs.is_empty() {
        return Err(AppError::Config(format!(
            "No certificates found in {cert_path:?}"
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| AppError::Config(format!("Failed to load IMAP TLS key {key_path:?}: {e}")))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Config(format!("Invalid IMAP TLS configuration: {e}")))?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Start the embedded IMAP4rev1 plain TCP (with optional STARTTLS) and/or implicit TLS listeners
/// configured in `state.config`, shutting down gracefully when `shutdown` signals `true`.
pub async fn serve_imap(state: AppState, shutdown: watch::Receiver<bool>) -> AppResult<()> {
    ensure_crypto_provider();

    let tls_acceptor = match (
        state.config.imap_tls_cert.as_deref(),
        state.config.imap_tls_key.as_deref(),
    ) {
        (Some(cert), Some(key)) => Some(build_tls_acceptor(cert, key)?),
        (Some(_), None) | (None, Some(_)) => {
            return Err(AppError::Config(
                "Both imap_tls_cert and imap_tls_key must be set to enable IMAP TLS/STARTTLS"
                    .to_string(),
            ));
        }
        (None, None) => None,
    };

    if state.config.imap_tls_bind.is_some() && tls_acceptor.is_none() {
        return Err(AppError::Config(
            "imap_tls_bind requires imap_tls_cert and imap_tls_key".to_string(),
        ));
    }

    let plain_listener = match state.config.imap_bind {
        Some(addr) => {
            let l = TcpListener::bind(addr)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to bind IMAP TCP {addr}: {e}")))?;
            info!(%addr, starttls = tls_acceptor.is_some(), "nogml IMAP4rev1 listener started");
            Some(l)
        }
        None => None,
    };

    let tls_listener = match state.config.imap_tls_bind {
        Some(addr) => {
            let l = TcpListener::bind(addr)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to bind IMAP TLS {addr}: {e}")))?;
            info!(%addr, "nogml IMAP4rev1 implicit TLS listener started");
            Some(l)
        }
        None => None,
    };

    match (plain_listener, tls_listener) {
        (Some(plain), Some(tls)) => {
            let s1 = state.clone();
            let rx1 = shutdown.clone();
            let acc1 = tls_acceptor.clone();
            let acc2 = tls_acceptor.expect("validated above");
            tokio::try_join!(
                serve_plain_listener(plain, s1, acc1, rx1),
                serve_tls_listener(tls, state, acc2, shutdown),
            )?;
            Ok(())
        }
        (Some(plain), None) => serve_plain_listener(plain, state, tls_acceptor, shutdown).await,
        (None, Some(tls)) => {
            let acc = tls_acceptor.expect("validated above");
            serve_tls_listener(tls, state, acc, shutdown).await
        }
        (None, None) => Ok(()),
    }
}

/// Accept plain TCP IMAP connections (supporting `STARTTLS` if `tls_acceptor` is provided)
/// on an already-bound [`TcpListener`].
pub async fn serve_plain_listener(
    listener: TcpListener,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) -> AppResult<()> {
    let mut handles = Vec::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, _peer)) => {
                        let st = state.clone();
                        let acc = tls_acceptor.clone();
                        let rx = shutdown.clone();
                        handles.push(tokio::spawn(async move {
                            handle_connection(ImapStream::Plain(tcp), st, acc, rx).await;
                        }));
                    }
                    Err(err) => {
                        warn!(%err, "IMAP TCP accept error");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// Accept implicit-TLS IMAP connections on an already-bound [`TcpListener`].
pub async fn serve_tls_listener(
    listener: TcpListener,
    state: AppState,
    tls_acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) -> AppResult<()> {
    let mut handles = Vec::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, _peer)) => {
                        let st = state.clone();
                        let acc = tls_acceptor.clone();
                        let rx = shutdown.clone();
                        handles.push(tokio::spawn(async move {
                            match acc.accept(tcp).await {
                                Ok(tls_stream) => {
                                    handle_connection(
                                        ImapStream::Tls(Box::new(tls_stream)),
                                        st,
                                        None,
                                        rx,
                                    ).await;
                                }
                                Err(err) => {
                                    warn!(%err, "IMAP implicit TLS handshake failed");
                                }
                            }
                        }));
                    }
                    Err(err) => {
                        warn!(%err, "IMAP TLS accept error");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
