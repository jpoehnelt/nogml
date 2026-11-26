//! RFC 2369 (`List-Unsubscribe`) and RFC 8058 (`List-Unsubscribe-Post`) header parsing.

use mail_parser::MessageParser;

use crate::{
    mime::payload,
    models::{MessagePartHeader, UnsubscribeInfo},
};

/// Canonical RFC 8058 `application/x-www-form-urlencoded` POST body for one-click unsubscribe.
pub const RFC8058_ONE_CLICK_BODY: &str = "List-Unsubscribe=One-Click";

/// Parse RFC 2369 `List-Unsubscribe` and RFC 8058 `List-Unsubscribe-Post` headers
/// from an extracted RFC 2822 header list.
pub fn parse_unsubscribe_headers(headers: &[MessagePartHeader]) -> Option<UnsubscribeInfo> {
    let mut https_url: Option<String> = None;
    let mut http_fallback_url: Option<String> = None;
    let mut mailto: Option<String> = None;
    let mut has_one_click_post = false;

    for header in headers {
        if header.name.eq_ignore_ascii_case("list-unsubscribe") {
            for uri in extract_angle_bracketed_uris(&header.value) {
                if has_forbidden_uri_chars(&uri) {
                    continue;
                }
                if starts_with_ignore_ascii_case(&uri, "https://") {
                    if https_url.is_none() && is_non_empty_http_uri(&uri) {
                        https_url = Some(uri);
                    }
                } else if starts_with_ignore_ascii_case(&uri, "http://") {
                    if http_fallback_url.is_none() && is_non_empty_http_uri(&uri) {
                        http_fallback_url = Some(uri);
                    }
                } else if starts_with_ignore_ascii_case(&uri, "mailto:")
                    && mailto.is_none()
                    && is_non_empty_mailto_uri(&uri)
                {
                    mailto = Some(uri);
                }
            }
        } else if header.name.eq_ignore_ascii_case("list-unsubscribe-post")
            && is_one_click_post_header(&header.value)
        {
            has_one_click_post = true;
        }
    }

    let selected_http_url = https_url.or(http_fallback_url);
    if selected_http_url.is_none() && mailto.is_none() {
        return None;
    }

    let one_click = has_one_click_post && selected_http_url.is_some();
    let post_body = one_click.then(|| RFC8058_ONE_CLICK_BODY.to_string());

    Some(UnsubscribeInfo {
        https_url: selected_http_url,
        mailto,
        one_click,
        post_body,
    })
}

/// Fast header-only RFC 2369 / RFC 8058 unsubscribe parser for raw RFC 2822 message bytes.
///
/// Only scans up to the end of the header block (`\r\n\r\n` or `\n\n`) so large MIME
/// bodies and attachments are never decoded when projecting [`crate::models::CompactMessage`].
pub fn parse_unsubscribe_from_raw(raw: &[u8]) -> Option<UnsubscribeInfo> {
    if raw.is_empty() {
        return None;
    }

    let header_slice = slice_header_block(raw);
    if !contains_ascii_case_insensitive(header_slice, b"list-unsubscribe") {
        return None;
    }

    let message = MessageParser::new().parse(header_slice)?;
    let headers = payload::extract_part_headers(&message.root_part());
    parse_unsubscribe_headers(&headers)
}

fn slice_header_block(raw: &[u8]) -> &[u8] {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return &raw[..pos + 4];
    }
    if let Some(pos) = find_subslice(raw, b"\n\n") {
        return &raw[..pos + 2];
    }
    raw
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|window| {
        window
            .iter()
            .zip(needle_lower.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn has_forbidden_uri_chars(uri: &str) -> bool {
    uri.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn is_non_empty_http_uri(uri: &str) -> bool {
    url::Url::parse(uri)
        .ok()
        .is_some_and(|parsed| parsed.host().is_some())
}

fn is_non_empty_mailto_uri(uri: &str) -> bool {
    let Some(rest) = uri.get(7..) else {
        return false;
    };
    let recipient_part = rest.split('?').next().unwrap_or("").trim();
    !recipient_part.is_empty() && recipient_part.contains('@')
}

/// Extract URIs enclosed in `<...>` from an RFC 2369 header value.
///
/// Strips RFC 5322 folding whitespace inside `<...>` per RFC 2369 section 2 and ignores
/// comments or delimiters outside angle brackets.
fn extract_angle_bracketed_uris(value: &str) -> Vec<String> {
    let mut uris = Vec::new();
    let mut rest = value;

    while let Some(lt) = rest.find('<') {
        let after_lt = &rest[lt + 1..];
        let Some(gt) = after_lt.find('>') else {
            break;
        };
        let inner = &after_lt[..gt];
        // Ignore nested `<` (malformed bracket nesting) by rejecting if inner contains `<`.
        if !inner.contains('<') {
            let cleaned: String = inner
                .chars()
                .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
                .collect();
            if !cleaned.is_empty() {
                uris.push(cleaned);
            }
        }
        rest = &after_lt[gt + 1..];
    }

    uris
}

/// Detect RFC 8058 `List-Unsubscribe=One-Click` directive (case-insensitive).
fn is_one_click_post_header(value: &str) -> bool {
    for part in value.split([';', ',']) {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim().eq_ignore_ascii_case("list-unsubscribe")
            && v.trim().eq_ignore_ascii_case("one-click")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(name: &str, value: &str) -> MessagePartHeader {
        MessagePartHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn parses_both_https_and_mailto_with_one_click() {
        let headers = vec![
            hdr(
                "List-Unsubscribe",
                "<https://example.com/unsub?id=42&sig=abc>, <mailto:unsub@example.com?subject=unsubscribe>",
            ),
            hdr("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
        ];

        let info = parse_unsubscribe_headers(&headers).expect("parsed unsubscribe");
        assert_eq!(
            info.https_url.as_deref(),
            Some("https://example.com/unsub?id=42&sig=abc")
        );
        assert_eq!(
            info.mailto.as_deref(),
            Some("mailto:unsub@example.com?subject=unsubscribe")
        );
        assert!(info.one_click);
        assert_eq!(
            info.post_body.as_deref(),
            Some("List-Unsubscribe=One-Click")
        );
    }

    #[test]
    fn parses_case_insensitive_one_click_post_and_mailto_first() {
        let headers = vec![
            hdr(
                "list-unsubscribe",
                "(comment) <mailto:leave@lists.example.org>, <HTTPS://lists.example.org/u/99>",
            ),
            hdr(
                "LIST-UNSUBSCRIBE-POST",
                "  list-unsubscribe = one-click ; extra=1",
            ),
        ];

        let info = parse_unsubscribe_headers(&headers).expect("parsed");
        assert_eq!(
            info.https_url.as_deref(),
            Some("HTTPS://lists.example.org/u/99")
        );
        assert_eq!(
            info.mailto.as_deref(),
            Some("mailto:leave@lists.example.org")
        );
        assert!(info.one_click);
        assert_eq!(
            info.post_body.as_deref(),
            Some("List-Unsubscribe=One-Click")
        );
    }

    #[test]
    fn parses_non_one_click_when_post_header_missing_or_unrelated() {
        let headers = vec![hdr(
            "List-Unsubscribe",
            "<https://example.com/prefs>, <mailto:optout@example.com>",
        )];
        let info = parse_unsubscribe_headers(&headers).expect("parsed");
        assert_eq!(info.https_url.as_deref(), Some("https://example.com/prefs"));
        assert_eq!(info.mailto.as_deref(), Some("mailto:optout@example.com"));
        assert!(!info.one_click);
        assert!(info.post_body.is_none());

        let headers_other_post = vec![
            hdr("List-Unsubscribe", "<https://example.com/prefs>"),
            hdr("List-Unsubscribe-Post", "List-Unsubscribe=Manual"),
        ];
        let info2 = parse_unsubscribe_headers(&headers_other_post).expect("parsed");
        assert!(!info2.one_click);
        assert!(info2.post_body.is_none());
    }

    #[test]
    fn mailto_only_with_one_click_header_is_not_one_click() {
        let headers = vec![
            hdr("List-Unsubscribe", "<mailto:unsub@example.com>"),
            hdr("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
        ];
        let info = parse_unsubscribe_headers(&headers).expect("parsed");
        assert!(info.https_url.is_none());
        assert_eq!(info.mailto.as_deref(), Some("mailto:unsub@example.com"));
        assert!(!info.one_click);
        assert!(info.post_body.is_none());
    }

    #[test]
    fn prefers_https_over_http_and_retains_http_for_ssrf_rejection_when_only_http() {
        let both = vec![hdr(
            "List-Unsubscribe",
            "<http://insecure.example.com/u>, <https://secure.example.com/u>",
        )];
        let info = parse_unsubscribe_headers(&both).expect("parsed");
        assert_eq!(
            info.https_url.as_deref(),
            Some("https://secure.example.com/u")
        );

        let only_http = vec![
            hdr("List-Unsubscribe", "<http://example.com/unsub>"),
            hdr("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
        ];
        let info_http = parse_unsubscribe_headers(&only_http).expect("parsed");
        assert_eq!(
            info_http.https_url.as_deref(),
            Some("http://example.com/unsub")
        );
        assert!(info_http.one_click);
    }

    #[test]
    fn rejects_malformed_and_unsupported_scheme_headers() {
        for bad in [
            "",
            "https://example.com/no-brackets",
            "<ftp://example.com/unsub>",
            "<file:///etc/passwd>",
            "<javascript:alert(1)>",
            "<https://>",
            "<mailto:>",
            "<mailto:?subject=no-address>",
            "<unclosed-bracket",
            "<<nested>>",
        ] {
            let headers = vec![hdr("List-Unsubscribe", bad)];
            assert!(
                parse_unsubscribe_headers(&headers).is_none(),
                "expected '{bad}' to parse as None"
            );
        }
    }

    #[test]
    fn parse_unsubscribe_from_raw_handles_folded_headers_and_skips_body() {
        let raw = concat!(
            "From: Newsletter <news@example.com>\r\n",
            "To: agent@example.com\r\n",
            "Subject: Weekly Digest\r\n",
            "List-Unsubscribe: <https://news.example.com/unsub?\r\n",
            " id=12345&token=xyz>,\r\n",
            " <mailto:unsub@news.example.com?subject=stop>\r\n",
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
            "\r\n",
            "Body text mentioning List-Unsubscribe: <https://evil.example.com/fake>\r\n"
        );

        let info = parse_unsubscribe_from_raw(raw.as_bytes()).expect("parsed");
        assert_eq!(
            info.https_url.as_deref(),
            Some("https://news.example.com/unsub?id=12345&token=xyz")
        );
        assert_eq!(
            info.mailto.as_deref(),
            Some("mailto:unsub@news.example.com?subject=stop")
        );
        assert!(info.one_click);
        assert_eq!(
            info.post_body.as_deref(),
            Some("List-Unsubscribe=One-Click")
        );

        // Plain email without List-Unsubscribe header returns None even if body mentions it.
        let body_only = concat!(
            "From: alice@example.com\r\n",
            "To: bob@example.com\r\n",
            "Subject: Regular mail\r\n",
            "\r\n",
            "List-Unsubscribe: <https://evil.example.com/in-body>\r\n"
        );
        assert!(parse_unsubscribe_from_raw(body_only.as_bytes()).is_none());
    }

    #[test]
    fn handles_multibyte_utf8_in_list_unsubscribe_without_panicking() {
        let headers = vec![
            hdr(
                "List-Unsubscribe",
                "<éééé>, <日本語テスト>, <https://example.com/u>",
            ),
            hdr("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
        ];
        let info = parse_unsubscribe_headers(&headers).expect("valid https url still parsed");
        assert_eq!(info.https_url.as_deref(), Some("https://example.com/u"));
        assert!(info.one_click);

        // Only multi-byte invalid URI must return None instead of panicking on char boundary.
        let only_utf8 = vec![hdr("List-Unsubscribe", "<éééé>")];
        assert!(parse_unsubscribe_headers(&only_utf8).is_none());

        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: agent@example.com\r\n",
            "Subject: UTF-8 Unsub\r\n",
            "List-Unsubscribe: <éééé>\r\n",
            "\r\n",
            "Hello\r\n"
        );
        assert!(parse_unsubscribe_from_raw(raw.as_bytes()).is_none());
    }
}
