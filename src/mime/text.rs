//! AI-first email text helpers: Gmail-style snippet generation, deterministic
//! quoted-reply stripping, and untrusted-content sanitization.

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
}
