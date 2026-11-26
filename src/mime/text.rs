//! AI-first email text helpers: Gmail-style snippet generation, deterministic
//! quoted-reply stripping, untrusted-content sanitization, tracking-pixel
//! stripping, and HTML link inspection.

use url::Url;

use crate::{mime::markdown::decode_html_entities, models::ExtractedLink};

const MAX_SNIPPET_CHARS: usize = 200;

/// Generate a plain-text Gmail-style snippet (`<= 200` Unicode chars, normalized whitespace).
pub fn generate_snippet(text: &str, html: Option<&str>) -> String {
    let source = if !text.trim().is_empty() {
        sanitize_untrusted_text(text)
    } else if let Some(html_body) = html {
        let converted = mail_parser::html_to_text(html_body);
        sanitize_untrusted_text(&converted)
    } else {
        return String::new();
    };

    let normalized: String = source.split_whitespace().collect::<Vec<_>>().join(" ");

    if normalized.chars().count() <= MAX_SNIPPET_CHARS {
        return normalized;
    }

    let truncated: String = normalized.chars().take(MAX_SNIPPET_CHARS - 3).collect();
    format!("{}...", truncated.trim_end())
}

/// Deterministically strip quoted reply blocks (`>` lines, `On ... wrote:`,
/// `-----Original Message-----`, Outlook horizontal-rule / `From:`/`Sent:` reply blocks).
///
/// Falls back to the original text if stripping removes all content.
pub fn strip_quoted_text(text: &str) -> String {
    if text.trim().is_empty() {
        return text.to_string();
    }

    let normalized = text.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // 1. Explicit original-message dividers.
        if is_original_message_divider(trimmed) {
            break;
        }

        // 2. Outlook horizontal-rule divider (10+ underscores).
        if is_outlook_divider(trimmed) {
            break;
        }

        // 3. Single-line `On <date/person> wrote:` attribution header.
        if is_on_wrote_line(trimmed) {
            break;
        }

        // 4. Two-line wrapped `On <date>\n<person> wrote:` attribution header.
        if i + 1 < lines.len() && is_wrapped_on_wrote(trimmed, lines[i + 1].trim()) {
            break;
        }

        // 5. Outlook-style quoted header block: `From: ...` followed shortly by `Sent:`/`Date:` and `To:`/`Subject:`.
        if is_outlook_header_block(&lines[i..]) {
            break;
        }

        // 6. Standard RFC-style `>` quoted lines.
        if trimmed.starts_with('>') {
            i += 1;
            continue;
        }

        kept.push(line);
        i += 1;
    }

    // Trim leading/trailing empty lines from kept content.
    while kept.first().is_some_and(|l| l.trim().is_empty()) {
        kept.remove(0);
    }
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }

    let result = kept.join("\n");
    if result.trim().is_empty() {
        text.to_string()
    } else {
        result
    }
}

fn is_original_message_divider(trimmed: &str) -> bool {
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("-----") && lower.ends_with("-----") {
        return lower.contains("original message")
            || lower.contains("forwarded message")
            || lower.contains("begin forwarded message");
    }
    if lower.starts_with("---") && lower.ends_with("---") {
        return lower.contains("original message") || lower.contains("forwarded message");
    }
    false
}

fn is_outlook_divider(trimmed: &str) -> bool {
    trimmed.len() >= 10 && trimmed.bytes().all(|b| b == b'_')
}

fn is_on_wrote_line(trimmed: &str) -> bool {
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("on ") && lower.ends_with("wrote:")
}

fn is_wrapped_on_wrote(line1: &str, line2: &str) -> bool {
    let l1 = line1.to_ascii_lowercase();
    let l2 = line2.to_ascii_lowercase();
    l1.starts_with("on ") && !l2.is_empty() && l2.ends_with("wrote:")
}

fn is_outlook_header_block(remaining: &[&str]) -> bool {
    let Some(first) = remaining.first() else {
        return false;
    };
    let lower_first = first.trim().to_ascii_lowercase();
    if !lower_first.starts_with("from:") {
        return false;
    }
    let window = &remaining[1..remaining.len().min(6)];
    let has_date_or_sent = window.iter().any(|l| {
        let lt = l.trim().to_ascii_lowercase();
        lt.starts_with("sent:") || lt.starts_with("date:")
    });
    let has_to_or_subject = window.iter().any(|l| {
        let lt = l.trim().to_ascii_lowercase();
        lt.starts_with("to:") || lt.starts_with("subject:")
    });
    has_date_or_sent && has_to_or_subject
}

/// Strip dangerous ASCII/C1 control chars, Unicode BiDi override/isolate chars,
/// and Unicode tag-smuggling chars to guard against prompt injection while
/// preserving normal text, newlines (`\n`, `\r`), tabs (`\t`), and emoji.
pub fn sanitize_untrusted_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_dangerous_char(ch) {
            continue;
        }
        out.push(ch);
    }
    out
}

fn is_dangerous_char(ch: char) -> bool {
    let code = ch as u32;
    match ch {
        // Safe whitespace controls
        '\n' | '\r' | '\t' => false,
        // C0 ASCII control characters & DEL
        '\u{0000}'..='\u{001F}' | '\u{007F}' => true,
        // C1 control characters
        '\u{0080}'..='\u{009F}' => true,
        // Unicode BiDi marks, embeddings, overrides, and isolates (incl. RLO U+202E)
        '\u{061C}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}' => true,
        // Unicode Tags block (invisible ASCII-smuggling characters)
        _ if (0xE0000..=0xE007F).contains(&code) => true,
        _ => false,
    }
}

// ============================================================================
// Tracking-Pixel Stripping & HTML Link Inspection
// ============================================================================

/// Remove tiny or hidden tracking-pixel `<img>` tags (such as `1x1`, `0x0`,
/// `display:none`, `visibility:hidden`, `opacity:0`, `width:1px`/`height:1px`,
/// or known remote open-tracking beacons) from HTML while preserving normal images
/// and surrounding markup verbatim.
pub fn strip_tracking_pixels(html: &str) -> String {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] != b'<' {
            let start = i;
            while i < len && bytes[i] != b'<' {
                i += 1;
            }
            out.push_str(&html[start..i]);
            continue;
        }

        // Preserve HTML comments verbatim.
        if html[i..].starts_with("<!--") {
            if let Some(end_rel) = html[i + 4..].find("-->") {
                let end = i + 4 + end_rel + 3;
                out.push_str(&html[i..end]);
                i = end;
            } else {
                out.push_str(&html[i..]);
                break;
            }
            continue;
        }

        // Match `<img` followed by ASCII whitespace, `/`, or `>`.
        if is_tag_start(html, i, "img")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            let tag_slice = &html[i..tag_end];
            let attrs = parse_tag_attrs(&html[i + 4..tag_end - 1]);
            if is_tracking_pixel_img(&attrs) {
                i = tag_end;
                continue;
            }
            out.push_str(tag_slice);
            i = tag_end;
            continue;
        }

        out.push('<');
        i += 1;
    }

    out
}

/// Extract `<a href="...">display</a>` links from HTML and flag `domain_mismatch: true`
/// whenever `display_text` looks like a URL or domain whose host does not match the
/// actual `href` host (case-insensitive, ignoring a leading `www.`).
pub fn extract_html_links(html: &str) -> Vec<ExtractedLink> {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut links = Vec::new();
    let mut i = 0;

    while i < len {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }

        if html[i..].starts_with("<!--") {
            if let Some(end_rel) = html[i + 4..].find("-->") {
                i = i + 4 + end_rel + 3;
            } else {
                break;
            }
            continue;
        }

        if is_tag_start(html, i, "script")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            i = skip_raw_block_end(html, tag_end, "script");
            continue;
        }

        if is_tag_start(html, i, "style")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            i = skip_raw_block_end(html, tag_end, "style");
            continue;
        }

        if is_tag_start(html, i, "a")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            let attr_slice = &html[i + 2..tag_end - 1];
            let self_closing = attr_slice.trim_end().ends_with('/');
            let attrs = parse_tag_attrs(attr_slice);
            let href = attrs
                .iter()
                .find(|(k, _)| k == "href")
                .map(|(_, v)| v.trim().to_string())
                .filter(|v| !v.is_empty());

            // Collect inner text until matching `</a>` (or next `<a ` if unclosed).
            let (inner_text, next_idx) = if self_closing {
                (String::new(), tag_end)
            } else {
                collect_anchor_text(html, tag_end)
            };
            i = next_idx;

            if let Some(href) = href {
                let display_text = inner_text.split_whitespace().collect::<Vec<_>>().join(" ");
                let domain_mismatch = link_has_domain_mismatch(&display_text, &href);
                links.push(ExtractedLink {
                    display_text,
                    href,
                    domain_mismatch,
                });
            }
            continue;
        }

        i += 1;
    }

    links
}

fn is_tag_start(html: &str, idx: usize, tag: &str) -> bool {
    let bytes = html.as_bytes();
    let tag_bytes = tag.as_bytes();
    let end = idx + 1 + tag_bytes.len();
    if end > bytes.len() || bytes[idx] != b'<' {
        return false;
    }
    if !bytes[idx + 1..end].eq_ignore_ascii_case(tag_bytes) {
        return false;
    }
    end == bytes.len()
        || bytes[end].is_ascii_whitespace()
        || bytes[end] == b'>'
        || bytes[end] == b'/'
}

fn find_tag_end(html: &str, start: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = start + 1;
    let mut quote: Option<u8> = None;
    while i < len {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(i + 1),
                _ => {}
            },
        }
        i += 1;
    }
    None
}

fn parse_tag_attrs(raw: &str) -> Vec<(String, String)> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut attrs = Vec::new();

    while i < len {
        while i < len && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= len {
            break;
        }
        let name_start = i;
        while i < len
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
            && bytes[i] != b'>'
        {
            i += 1;
        }
        if i == name_start {
            i += 1;
            continue;
        }
        let name = raw[name_start..i].to_ascii_lowercase();

        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let value = if i < len && bytes[i] == b'=' {
            i += 1;
            while i < len && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let val_start = i;
                while i < len && bytes[i] != q {
                    i += 1;
                }
                let val = decode_html_entities(&raw[val_start..i]);
                if i < len {
                    i += 1;
                }
                val
            } else {
                let val_start = i;
                while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                decode_html_entities(&raw[val_start..i])
            }
        } else {
            String::new()
        };

        attrs.push((name, value));
    }

    attrs
}

fn parse_pixel_dimension(raw: &str) -> Option<f64> {
    let mut trimmed = raw.trim().to_ascii_lowercase();
    if let Some(before_important) = trimmed.strip_suffix("!important") {
        trimmed = before_important.trim().to_string();
    }
    let numeric = trimmed.strip_suffix("px").unwrap_or(&trimmed).trim();
    if numeric.is_empty() {
        return None;
    }
    numeric
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
}

fn is_tracking_pixel_img(attrs: &[(String, String)]) -> bool {
    let mut explicit_width: Option<f64> = None;
    let mut explicit_height: Option<f64> = None;
    let mut src: Option<&str> = None;

    for (name, val) in attrs {
        match name.as_str() {
            "hidden" => return true,
            "width" => {
                if let Some(px) = parse_pixel_dimension(val) {
                    if px <= 1.0 {
                        return true;
                    }
                    explicit_width = Some(px);
                }
            }
            "height" => {
                if let Some(px) = parse_pixel_dimension(val) {
                    if px <= 1.0 {
                        return true;
                    }
                    explicit_height = Some(px);
                }
            }
            "style" => {
                if style_indicates_tracking_pixel(val) {
                    return true;
                }
            }
            "src" => {
                src = Some(val.as_str());
            }
            _ => {}
        }
    }

    // Also strip remote open-tracking beacons when no normal (> 1px) dimensions are declared.
    if explicit_width.is_none()
        && explicit_height.is_none()
        && let Some(raw_src) = src
        && is_remote_tracking_beacon_url(raw_src)
    {
        return true;
    }

    false
}

fn style_indicates_tracking_pixel(style: &str) -> bool {
    for decl in style.split(';') {
        let Some((raw_prop, raw_val)) = decl.split_once(':') else {
            continue;
        };
        let prop = raw_prop.trim().to_ascii_lowercase();
        let val = raw_val.trim().to_ascii_lowercase();
        let val = val.strip_suffix("!important").unwrap_or(&val).trim();
        match prop.as_str() {
            "display" if val == "none" => return true,
            "visibility" if val == "hidden" => return true,
            "opacity" if parse_pixel_dimension(val).is_some_and(|v| v == 0.0) => return true,
            "width" | "max-width" | "height" | "max-height"
                if parse_pixel_dimension(val).is_some_and(|px| px <= 1.0) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_remote_tracking_beacon_url(raw_src: &str) -> bool {
    let trimmed = raw_src.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    let path = parsed.path().to_ascii_lowercase();
    [
        "/pixel.gif",
        "/pixel.png",
        "/1x1.gif",
        "/1x1.png",
        "/spacer.gif",
        "/open.gif",
        "/open.png",
        "/beacon.gif",
        "/beacon.png",
        "/track/open",
        "/wf/open",
    ]
    .iter()
    .any(|pattern| path.ends_with(pattern) || path.contains(&format!("{pattern}/")))
}

fn skip_raw_block_end(html: &str, start: usize, tag: &str) -> usize {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let tag_bytes = tag.as_bytes();
    let mut i = start;

    while i < len {
        if bytes[i] == b'<'
            && i + 2 + tag_bytes.len() <= len
            && bytes[i + 1] == b'/'
            && bytes[i + 2..i + 2 + tag_bytes.len()].eq_ignore_ascii_case(tag_bytes)
        {
            let after = i + 2 + tag_bytes.len();
            if after < len
                && (bytes[after] == b'>' || bytes[after].is_ascii_whitespace())
                && let Some(gt_rel) = html[after..].find('>')
            {
                return after + gt_rel + 1;
            }
        }
        i += 1;
    }
    len
}

fn collect_anchor_text(html: &str, start: usize) -> (String, usize) {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = start;
    let mut text = String::new();

    while i < len {
        if bytes[i] != b'<' {
            let chunk_start = i;
            while i < len && bytes[i] != b'<' {
                i += 1;
            }
            text.push_str(&decode_html_entities(&html[chunk_start..i]));
            continue;
        }

        if html[i..].starts_with("<!--") {
            if let Some(end_rel) = html[i + 4..].find("-->") {
                i = i + 4 + end_rel + 3;
            } else {
                return (text, len);
            }
            continue;
        }

        // Matching closing `</a>`
        if i + 3 <= len
            && bytes[i + 1] == b'/'
            && bytes[i + 2].eq_ignore_ascii_case(&b'a')
            && (i + 3 == len || bytes[i + 3] == b'>' || bytes[i + 3].is_ascii_whitespace())
            && let Some(gt_rel) = html[i + 3..].find('>')
        {
            return (text, i + 3 + gt_rel + 1);
        }

        // Unclosed `<a>` followed immediately by another `<a>`: stop before the new anchor.
        if is_tag_start(html, i, "a") {
            return (text, i);
        }

        if is_tag_start(html, i, "script")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            i = skip_raw_block_end(html, tag_end, "script");
            continue;
        }

        if is_tag_start(html, i, "style")
            && let Some(tag_end) = find_tag_end(html, i)
        {
            i = skip_raw_block_end(html, tag_end, "style");
            continue;
        }

        if let Some(tag_end) = find_tag_end(html, i) {
            i = tag_end;
            continue;
        }

        text.push('<');
        i += 1;
    }

    (text, len)
}

fn normalize_host(host: &str) -> String {
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    lower.strip_prefix("www.").unwrap_or(&lower).to_string()
}

fn extract_href_host(href: &str) -> Option<String> {
    let cleaned = sanitize_untrusted_text(href);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = if trimmed.starts_with("//") {
        Url::parse(&format!("https:{trimmed}")).ok()?
    } else {
        Url::parse(trimmed).ok()?
    };
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    parsed.host_str().map(normalize_host)
}

const COMMON_FILE_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "md", "json", "xml", "yaml",
    "yml", "html", "htm", "css", "js", "ts", "rs", "py", "go", "java", "png", "jpg", "jpeg", "gif",
    "svg", "webp", "mp3", "mp4", "zip", "tar", "gz", "ics", "eml", "log", "toml", "ini", "env",
    "sh", "exe", "dmg",
];

fn extract_display_host(display_text: &str) -> Option<String> {
    let cleaned = sanitize_untrusted_text(display_text);
    let trimmed = cleaned
        .trim()
        .trim_end_matches(['.', ',', ';', ':', '!', '?', ')']);
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let parsed = Url::parse(trimmed).ok()?;
        return parsed.host_str().map(normalize_host);
    }

    // Do not treat email addresses (`user@example.com`) as web URLs.
    if trimmed.contains('@') || trimmed.contains("://") {
        return None;
    }

    let has_path = trimmed.contains('/');
    let host_and_port = trimmed.split(['/', '?', '#']).next()?;
    let host_candidate = match host_and_port.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host_and_port,
    };

    if !host_candidate.contains('.')
        || host_candidate.starts_with('.')
        || host_candidate.ends_with('.')
        || host_candidate.contains("..")
    {
        return None;
    }

    let labels: Vec<&str> = host_candidate.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }

    let tld = labels.last()?.to_ascii_lowercase();
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }

    // Avoid flagging bare filenames like `report.pdf` or `README.md` as domain links.
    let starts_with_www = labels[0].eq_ignore_ascii_case("www");
    if !has_path && !starts_with_www && COMMON_FILE_EXTENSIONS.contains(&tld.as_str()) {
        return None;
    }

    Some(normalize_host(host_candidate))
}

fn link_has_domain_mismatch(display_text: &str, href: &str) -> bool {
    let Some(display_host) = extract_display_host(display_text) else {
        return false;
    };
    match extract_href_host(href) {
        Some(href_host) => display_host != href_host,
        // Display text looks like a web URL/domain, but href has no HTTP(S) host
        // (for example `javascript:...` or `mailto:...`).
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_normalizes_whitespace_and_truncates_to_200_chars() {
        assert_eq!(
            generate_snippet("  Hello \n\t  world!  ", None),
            "Hello world!"
        );

        let long_text = "a".repeat(250);
        let snippet = generate_snippet(&long_text, None);
        assert!(snippet.chars().count() <= 200);
        assert!(snippet.ends_with("..."));

        let exact_200 = "x".repeat(200);
        assert_eq!(generate_snippet(&exact_200, None), exact_200);
    }

    #[test]
    fn snippet_falls_back_to_html_when_text_empty() {
        let html = "<html><body><h1>Hello</h1><p>World &amp; friends!</p></body></html>";
        let snippet = generate_snippet("   ", Some(html));
        assert!(snippet.contains("Hello"));
        assert!(snippet.contains("World & friends!"));
        assert!(!snippet.contains("<h1>"));
    }

    #[test]
    fn snippet_handles_multibyte_unicode_safely() {
        let emoji_text = "🎉 ".repeat(150);
        let snippet = generate_snippet(&emoji_text, None);
        assert!(snippet.chars().count() <= 200);
    }

    #[test]
    fn strip_quoted_removes_on_wrote_and_angle_quotes() {
        let body = "Sounds good, see you at 3pm!\n\nOn Tue, Nov 25, 2026 at 9:00 AM Alice <alice@example.com> wrote:\n> Can we meet today?\n> Let me know.";
        assert_eq!(strip_quoted_text(body), "Sounds good, see you at 3pm!");
    }

    #[test]
    fn strip_quoted_removes_wrapped_on_wrote() {
        let body = "Approved.\n\nOn Tue, Nov 25, 2026 at 9:00 AM\nAlice <alice@example.com> wrote:\n> Please approve.";
        assert_eq!(strip_quoted_text(body), "Approved.");
    }

    #[test]
    fn strip_quoted_removes_original_message_and_outlook_blocks() {
        let body = "Thanks!\r\n\r\n-----Original Message-----\r\nFrom: Bob\r\nSent: Monday\r\nSubject: Hi\r\n\r\nOld body";
        assert_eq!(strip_quoted_text(body), "Thanks!");

        let outlook = "Got it.\n\nFrom: Alice <a@b.com>\nSent: Tue, Nov 25\nTo: Bob <b@b.com>\nSubject: Test\n\nPrevious text";
        assert_eq!(strip_quoted_text(outlook), "Got it.");
    }

    #[test]
    fn strip_quoted_removes_inline_angle_quotes_and_falls_back_if_empty() {
        let inline = "> quoted line\nMy reply here\n>> deeper quote";
        assert_eq!(strip_quoted_text(inline), "My reply here");

        let only_quotes = "> everything is quoted\n> nothing new";
        assert_eq!(strip_quoted_text(only_quotes), only_quotes);
    }

    #[test]
    fn sanitize_strips_control_and_bidi_preserves_safe_chars() {
        let dirty =
            "Hello\x00\x07\x1B[31m\u{202E}evil\u{202C}\u{2066}iso\u{2069}\u{E0041}\nLine\t2\r\n👨‍👩‍👧‍👦";
        let clean = sanitize_untrusted_text(dirty);
        assert_eq!(clean, "Hello[31meviliso\nLine\t2\r\n👨‍👩‍👧‍👦");
    }

    #[test]
    fn strip_tracking_pixels_removes_beacons_and_preserves_normal_images() {
        let html = concat!(
            "<p>Welcome!</p>",
            r#"<img src="https://cdn.example.com/banner.png" width="600" height="200" alt="Banner">"#,
            r#"<img src="https://track.example.com/open.gif" width="1" height="1" alt="">"#,
            r#"<img src="https://track.example.com/zero.png" width="0" height="0">"#,
            r#"<img src="https://track.example.com/hidden.png" style="display: none; border: 0;">"#,
            r#"<img src="https://track.example.com/css1px.png" style="width: 1px; height: 1px;">"#,
            r#"<img src="https://track.example.com/wf/open?id=123">"#,
            r#"<img src="https://cdn.example.com/photo.jpg" alt="Photo">"#,
        );
        let stripped = strip_tracking_pixels(html);
        assert!(stripped.contains("<p>Welcome!</p>"));
        assert!(stripped.contains("banner.png"));
        assert!(stripped.contains("photo.jpg"));
        assert!(!stripped.contains("open.gif"));
        assert!(!stripped.contains("zero.png"));
        assert!(!stripped.contains("hidden.png"));
        assert!(!stripped.contains("css1px.png"));
        assert!(!stripped.contains("/wf/open"));
    }

    #[test]
    fn extract_html_links_flags_spoofed_domains_and_allows_legitimate_links() {
        let html = concat!(
            r#"<p>Verify at <a href="https://evil.example/login">https://bank.example/verify</a></p>"#,
            r#"<p>Or visit <a href="https://evil.example/phish"><span>bank.example/account</span></a></p>"#,
            r#"<p>Legit <a href="https://www.bank.example/help">https://BANK.EXAMPLE/help</a></p>"#,
            r#"<p>Docs <a href="https://docs.example.com/guide">Read the guide</a></p>"#,
            r#"<p>File <a href="https://cdn.example.com/files/report.pdf">report.pdf</a></p>"#,
            r#"<p>Mail <a href="mailto:alice@example.com">alice@example.com</a></p>"#,
            r#"<p>JS spoof <a href="javascript:alert(1)">https://trusted.example</a></p>"#,
        );
        let links = extract_html_links(html);
        assert_eq!(links.len(), 7);

        assert_eq!(links[0].display_text, "https://bank.example/verify");
        assert_eq!(links[0].href, "https://evil.example/login");
        assert!(links[0].domain_mismatch);

        assert_eq!(links[1].display_text, "bank.example/account");
        assert_eq!(links[1].href, "https://evil.example/phish");
        assert!(links[1].domain_mismatch);

        assert_eq!(links[2].display_text, "https://BANK.EXAMPLE/help");
        assert_eq!(links[2].href, "https://www.bank.example/help");
        assert!(!links[2].domain_mismatch);

        assert_eq!(links[3].display_text, "Read the guide");
        assert!(!links[3].domain_mismatch);

        assert_eq!(links[4].display_text, "report.pdf");
        assert!(!links[4].domain_mismatch);

        assert_eq!(links[5].display_text, "alice@example.com");
        assert!(!links[5].domain_mismatch);

        assert_eq!(links[6].display_text, "https://trusted.example");
        assert!(links[6].domain_mismatch);
    }
}
