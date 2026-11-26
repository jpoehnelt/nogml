//! Pure-Rust HTML-to-Markdown converter for AI-first email reading.
//!
//! Converts email HTML into concise, link-preserving Markdown without external
//! C dependencies:
//! - Strips `<script>`, `<style>`, `<head>`, `<noscript>`, `<template>`, and HTML comments.
//! - Converts headings `<h1>`..`<h6>`, links `<a href="...">text</a>` (stripping
//!   `javascript:`/`vbscript:`/`data:` URLs), lists `<ul>`/`<ol>`/`<li>`, paragraphs `<p>`,
//!   line breaks `<br>`, `<blockquote>`, `<code>`/`<pre>`, `<strong>`/`<b>`, `<em>`/`<i>`,
//!   `<hr>`, and `<table>` rows/cells.
//! - Decodes common named and numeric (`&#...;` / `&#x...;`) HTML entities and collapses
//!   excess whitespace cleanly.

const MAX_DOM_DEPTH: usize = 96;
const THIN_TEXT_MAX_CHARS: usize = 40;
const EXTENDED_THIN_TEXT_MAX_CHARS: usize = 120;

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Element {
        tag: String,
        attrs: Vec<(String, String)>,
        children: Vec<Node>,
    },
}

impl Node {
    fn attr(&self, name: &str) -> Option<&str> {
        match self {
            Node::Element { attrs, .. } => attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str()),
            Node::Text(_) => None,
        }
    }
}

/// Convert HTML into concise, link-preserving Markdown.
pub fn html_to_markdown(html: &str) -> String {
    if html.trim().is_empty() {
        return String::new();
    }

    let nodes = parse_html_nodes(html);
    let mut out = String::new();
    render_nodes(&nodes, &mut out, RenderCtx::default());
    normalize_markdown_output(&out)
}

/// Decide whether `text_body` is empty or thin compared to `html_body`, and if so return
/// `(converted_markdown, true)`; otherwise return `(text_body.to_string(), false)`.
///
/// Handles HTML-only emails and multipart emails whose `text/plain` part is a short stub
/// such as `"Please view this email in HTML"`.
pub fn select_body_or_html_markdown(text_body: &str, html_body: Option<&str>) -> (String, bool) {
    let Some(raw_html) = html_body.filter(|h| !h.trim().is_empty()) else {
        return (text_body.to_string(), false);
    };

    let trimmed_text = text_body.trim();
    if trimmed_text.is_empty() {
        let md = html_to_markdown(raw_html);
        if !md.trim().is_empty() {
            return (md, true);
        }
        return (text_body.to_string(), false);
    }

    let text_chars = trimmed_text.chars().count();
    if text_chars >= EXTENDED_THIN_TEXT_MAX_CHARS {
        return (text_body.to_string(), false);
    }

    let md = html_to_markdown(raw_html);
    let md_trimmed = md.trim();
    let md_chars = md_trimmed.chars().count();
    if md_chars == 0 {
        return (text_body.to_string(), false);
    }

    let is_thin_short = text_chars < THIN_TEXT_MAX_CHARS
        && md_chars >= THIN_TEXT_MAX_CHARS
        && md_chars >= text_chars.saturating_mul(2);
    let is_thin_stub = text_chars < EXTENDED_THIN_TEXT_MAX_CHARS
        && md_chars >= 80
        && md_chars >= text_chars.saturating_mul(3);

    if is_thin_short || is_thin_stub {
        (md, true)
    } else {
        (text_body.to_string(), false)
    }
}

/// Decode common named and numeric HTML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`,
/// `&#39;`, `&nbsp;`, `&#...;`, `&#x...;`, etc.).
pub fn decode_html_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'&'
            && let Some(semi_rel) = input[i + 1..].find(';')
            && semi_rel > 0
            && semi_rel <= 16
        {
            let entity = &input[i + 1..i + 1 + semi_rel];
            if let Some(decoded) = decode_single_entity(entity) {
                out.push_str(&decoded);
                i += semi_rel + 2;
                continue;
            }
        }

        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn decode_single_entity(entity: &str) -> Option<String> {
    if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        let code = u32::from_str_radix(hex, 16).ok()?;
        let ch = decode_numeric_codepoint(code)?;
        return Some(ch.to_string());
    }
    if let Some(dec) = entity.strip_prefix('#') {
        let code = dec.parse::<u32>().ok()?;
        let ch = decode_numeric_codepoint(code)?;
        return Some(ch.to_string());
    }

    let mapped = match entity {
        "amp" | "AMP" => "&",
        "lt" | "LT" => "<",
        "gt" | "GT" => ">",
        "quot" | "QUOT" => "\"",
        "apos" => "'",
        "nbsp" => " ",
        "mdash" => "\u{2014}",
        "ndash" => "\u{2013}",
        "hellip" => "...",
        "lsquo" => "'",
        "rsquo" => "'",
        "ldquo" => "\"",
        "rdquo" => "\"",
        "bull" => "*",
        "middot" => "\u{00B7}",
        "copy" => "(c)",
        "reg" => "(R)",
        "trade" => "(TM)",
        "laquo" => "<<",
        "raquo" => ">>",
        "times" => "x",
        "divide" => "/",
        "plusmn" => "+/-",
        "euro" => "\u{20AC}",
        "pound" => "\u{00A3}",
        "yen" => "\u{00A5}",
        "cent" => "\u{00A2}",
        "sect" => "\u{00A7}",
        "ensp" | "emsp" | "thinsp" => " ",
        _ => return None,
    };
    Some(mapped.to_string())
}

fn decode_numeric_codepoint(code: u32) -> Option<char> {
    if code == 0 {
        return None;
    }
    if code == 0xA0 {
        return Some(' ');
    }
    char::from_u32(code)
}

// ============================================================================
// Lightweight Pure-Rust HTML Parser
// ============================================================================

#[derive(Debug)]
enum Token {
    StartTag {
        name: String,
        attrs: Vec<(String, String)>,
        self_closing: bool,
    },
    EndTag {
        name: String,
    },
    Text(String),
}

fn is_void_tag(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn is_ignored_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "script" | "style" | "head" | "noscript" | "template" | "svg"
    )
}

fn tokenize_html(html: &str) -> Vec<Token> {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut tokens = Vec::new();
    let mut text_buf = String::new();

    let flush_text = |buf: &mut String, out: &mut Vec<Token>| {
        if !buf.is_empty() {
            out.push(Token::Text(std::mem::take(buf)));
        }
    };

    while i < len {
        if bytes[i] != b'<' {
            let start = i;
            while i < len && bytes[i] != b'<' {
                i += 1;
            }
            text_buf.push_str(&html[start..i]);
            continue;
        }

        // HTML comment: <!-- ... -->
        if html[i..].starts_with("<!--") {
            flush_text(&mut text_buf, &mut tokens);
            if let Some(end_rel) = html[i + 4..].find("-->") {
                i = i + 4 + end_rel + 3;
            } else {
                break;
            }
            continue;
        }

        // CDATA: <![CDATA[ ... ]]>
        if html[i..].starts_with("<![CDATA[") {
            if let Some(end_rel) = html[i + 9..].find("]]>") {
                text_buf.push_str(&html[i + 9..i + 9 + end_rel]);
                i = i + 9 + end_rel + 3;
            } else {
                break;
            }
            continue;
        }

        // DOCTYPE / declaration / XML PI: <!...> or <?...>
        if i + 1 < len && (bytes[i + 1] == b'!' || bytes[i + 1] == b'?') {
            flush_text(&mut text_buf, &mut tokens);
            if let Some(end_rel) = html[i + 2..].find('>') {
                i = i + 2 + end_rel + 1;
            } else {
                break;
            }
            continue;
        }

        // End tag: </tag ...>
        if i + 1 < len && bytes[i + 1] == b'/' {
            let mut j = i + 2;
            while j < len && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < len
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-' || bytes[j] == b':')
            {
                j += 1;
            }
            let name = html[name_start..j].to_ascii_lowercase();
            if let Some(gt_rel) = html[j..].find('>') {
                flush_text(&mut text_buf, &mut tokens);
                if !name.is_empty() {
                    tokens.push(Token::EndTag { name });
                }
                i = j + gt_rel + 1;
                continue;
            } else {
                // Unclosed tag at EOF: treat '<' as literal text
                text_buf.push('<');
                i += 1;
                continue;
            }
        }

        // Start tag: <tag attr="val" ...>
        if i + 1 < len
            && bytes[i + 1].is_ascii_alphabetic()
            && let Some(parsed_tag) = parse_start_tag(html, i)
        {
            flush_text(&mut text_buf, &mut tokens);

            // For raw ignored blocks (<script>, <style>, <noscript>, <head>), skip raw content
            // until matching closing tag so '<' inside JS/CSS cannot confuse tokenization.
            if !parsed_tag.self_closing && is_ignored_block_tag(&parsed_tag.name) {
                i = skip_until_end_tag(html, parsed_tag.next_idx, &parsed_tag.name);
                continue;
            }

            tokens.push(Token::StartTag {
                name: parsed_tag.name,
                attrs: parsed_tag.attrs,
                self_closing: parsed_tag.self_closing,
            });
            i = parsed_tag.next_idx;
            continue;
        }

        // Literal '<' (e.g. "x < 5")
        text_buf.push('<');
        i += 1;
    }

    flush_text(&mut text_buf, &mut tokens);
    tokens
}

struct ParsedStartTag {
    name: String,
    attrs: Vec<(String, String)>,
    self_closing: bool,
    next_idx: usize,
}

fn parse_start_tag(html: &str, start: usize) -> Option<ParsedStartTag> {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = start + 1;

    let name_start = i;
    while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b':') {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let name = html[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    let mut self_closing = false;

    loop {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return None;
        }
        if bytes[i] == b'>' {
            return Some(ParsedStartTag {
                name,
                attrs,
                self_closing,
                next_idx: i + 1,
            });
        }
        if bytes[i] == b'/' {
            if i + 1 < len && bytes[i + 1] == b'>' {
                return Some(ParsedStartTag {
                    name,
                    attrs,
                    self_closing: true,
                    next_idx: i + 2,
                });
            }
            self_closing = true;
            i += 1;
            continue;
        }

        let attr_start = i;
        while i < len
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'>'
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if i == attr_start {
            i += 1;
            continue;
        }
        let attr_name = html[attr_start..i].to_ascii_lowercase();

        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let attr_value = if i < len && bytes[i] == b'=' {
            i += 1;
            while i < len && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let val_start = i;
                while i < len && bytes[i] != quote {
                    i += 1;
                }
                let raw_val = &html[val_start..i];
                if i < len {
                    i += 1;
                }
                decode_html_entities(raw_val)
            } else {
                let val_start = i;
                while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                decode_html_entities(&html[val_start..i])
            }
        } else {
            String::new()
        };

        attrs.push((attr_name, attr_value));
    }
}

fn skip_until_end_tag(html: &str, start: usize, tag_name: &str) -> usize {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = start;
    let tag_bytes = tag_name.as_bytes();

    while i < len {
        if bytes[i] == b'<' && i + 2 + tag_bytes.len() <= len && bytes[i + 1] == b'/' {
            let candidate = &bytes[i + 2..i + 2 + tag_bytes.len()];
            if candidate.eq_ignore_ascii_case(tag_bytes) {
                let after = i + 2 + tag_bytes.len();
                if after < len
                    && (bytes[after] == b'>' || bytes[after].is_ascii_whitespace())
                    && let Some(gt_rel) = html[after..].find('>')
                {
                    return after + gt_rel + 1;
                }
            }
        }
        i += 1;
    }

    len
}

struct OpenElem {
    tag: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

fn parse_html_nodes(html: &str) -> Vec<Node> {
    let tokens = tokenize_html(html);
    let mut root_children: Vec<Node> = Vec::new();
    let mut stack: Vec<OpenElem> = Vec::new();

    let push_node = |node: Node, stack: &mut Vec<OpenElem>, root: &mut Vec<Node>| {
        if let Some(top) = stack.last_mut() {
            top.children.push(node);
        } else {
            root.push(node);
        }
    };

    for tok in tokens {
        match tok {
            Token::Text(raw) => {
                let decoded = decode_html_entities(&raw);
                if !decoded.is_empty() {
                    push_node(Node::Text(decoded), &mut stack, &mut root_children);
                }
            }
            Token::StartTag {
                name,
                attrs,
                self_closing,
            } => {
                if is_ignored_block_tag(&name) {
                    continue;
                }

                // Implicit close for unclosed sibling tags like <li>...<li>, <p>...<p>, <td>...<td>, <tr>...<tr>
                if should_auto_close_previous(&stack, &name)
                    && let Some(closed) = stack.pop()
                {
                    push_node(
                        Node::Element {
                            tag: closed.tag,
                            attrs: closed.attrs,
                            children: closed.children,
                        },
                        &mut stack,
                        &mut root_children,
                    );
                }

                if self_closing || is_void_tag(&name) {
                    push_node(
                        Node::Element {
                            tag: name,
                            attrs,
                            children: Vec::new(),
                        },
                        &mut stack,
                        &mut root_children,
                    );
                } else if stack.len() < MAX_DOM_DEPTH {
                    stack.push(OpenElem {
                        tag: name,
                        attrs,
                        children: Vec::new(),
                    });
                }
            }
            Token::EndTag { name } => {
                if let Some(pos) = stack.iter().rposition(|el| el.tag == name) {
                    while stack.len() > pos {
                        if let Some(closed) = stack.pop() {
                            push_node(
                                Node::Element {
                                    tag: closed.tag,
                                    attrs: closed.attrs,
                                    children: closed.children,
                                },
                                &mut stack,
                                &mut root_children,
                            );
                        }
                    }
                }
            }
        }
    }

    while let Some(closed) = stack.pop() {
        push_node(
            Node::Element {
                tag: closed.tag,
                attrs: closed.attrs,
                children: closed.children,
            },
            &mut stack,
            &mut root_children,
        );
    }

    root_children
}

fn should_auto_close_previous(stack: &[OpenElem], next_tag: &str) -> bool {
    let Some(top) = stack.last() else {
        return false;
    };
    matches!(
        (top.tag.as_str(), next_tag),
        ("li", "li")
            | (
                "p",
                "p" | "div"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "ul"
                    | "ol"
                    | "table"
                    | "blockquote"
                    | "pre"
                    | "hr",
            )
            | ("td" | "th", "td" | "th" | "tr")
            | ("tr", "tr")
            | ("dt" | "dd", "dt" | "dd")
    )
}

// ============================================================================
// Markdown Renderer
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
struct RenderCtx {
    in_pre: bool,
    list_depth: usize,
    depth: usize,
}

fn render_nodes(nodes: &[Node], out: &mut String, ctx: RenderCtx) {
    if ctx.depth > MAX_DOM_DEPTH {
        return;
    }
    for node in nodes {
        render_node(node, out, ctx);
    }
}

fn render_node(node: &Node, out: &mut String, ctx: RenderCtx) {
    match node {
        Node::Text(text) => {
            if ctx.in_pre {
                out.push_str(&text.replace("\r\n", "\n"));
            } else {
                push_collapsed_inline_text(out, text);
            }
        }
        Node::Element {
            tag,
            attrs: _,
            children,
        } => {
            let child_ctx = RenderCtx {
                depth: ctx.depth + 1,
                ..ctx
            };
            match tag.as_str() {
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                    let level = (tag.as_bytes()[1] - b'0') as usize;
                    let inner = render_inline_fragment(children, child_ctx);
                    let trimmed = collapse_inline_whitespace(&inner);
                    if !trimmed.is_empty() {
                        ensure_blank_line(out);
                        for _ in 0..level {
                            out.push('#');
                        }
                        out.push(' ');
                        out.push_str(&trimmed);
                        ensure_blank_line(out);
                    }
                }
                "p" => {
                    let mut inner = String::new();
                    render_nodes(children, &mut inner, child_ctx);
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        ensure_blank_line(out);
                        out.push_str(trimmed);
                        ensure_blank_line(out);
                    }
                }
                "br" => {
                    trim_trailing_spaces(out);
                    out.push('\n');
                }
                "hr" => {
                    ensure_blank_line(out);
                    out.push_str("---");
                    ensure_blank_line(out);
                }
                "strong" | "b" => {
                    render_inline_wrapper(children, out, child_ctx, "**", "**");
                }
                "em" | "i" => {
                    render_inline_wrapper(children, out, child_ctx, "*", "*");
                }
                "s" | "del" | "strike" => {
                    render_inline_wrapper(children, out, child_ctx, "~~", "~~");
                }
                "code" => {
                    if ctx.in_pre {
                        render_nodes(children, out, child_ctx);
                    } else {
                        let inner = collect_raw_text(children);
                        let trimmed = inner.trim();
                        if !trimmed.is_empty() {
                            if trimmed.contains('`') {
                                out.push_str("`` ");
                                out.push_str(trimmed);
                                out.push_str(" ``");
                            } else {
                                out.push('`');
                                out.push_str(trimmed);
                                out.push('`');
                            }
                        }
                    }
                }
                "pre" => {
                    let mut raw = String::new();
                    let pre_ctx = RenderCtx {
                        in_pre: true,
                        ..child_ctx
                    };
                    render_nodes(children, &mut raw, pre_ctx);
                    let trimmed = raw.trim_matches('\n');
                    if !trimmed.trim().is_empty() {
                        ensure_blank_line(out);
                        let fence = if trimmed.contains("```") {
                            "~~~~"
                        } else {
                            "```"
                        };
                        out.push_str(fence);
                        out.push('\n');
                        out.push_str(trimmed);
                        out.push('\n');
                        out.push_str(fence);
                        ensure_blank_line(out);
                    }
                }
                "blockquote" => {
                    let mut inner = String::new();
                    render_nodes(children, &mut inner, child_ctx);
                    let normalized = normalize_markdown_output(&inner);
                    if !normalized.is_empty() {
                        ensure_blank_line(out);
                        for (idx, line) in normalized.lines().enumerate() {
                            if idx > 0 {
                                out.push('\n');
                            }
                            if line.trim().is_empty() {
                                out.push('>');
                            } else {
                                out.push_str("> ");
                                out.push_str(line);
                            }
                        }
                        ensure_blank_line(out);
                    }
                }
                "a" => {
                    let href = node.attr("href").and_then(sanitize_href);
                    let inner = render_inline_fragment(children, child_ctx);
                    let label = collapse_inline_whitespace(&inner);
                    if label.is_empty() {
                        return;
                    }
                    if let Some(url) = href {
                        let escaped_url = url.replace(')', "%29");
                        out.push('[');
                        out.push_str(&label);
                        out.push_str("](");
                        out.push_str(&escaped_url);
                        out.push(')');
                    } else {
                        out.push_str(&label);
                    }
                }
                "img" => {
                    if let Some(alt) = node.attr("alt") {
                        let clean_alt = collapse_inline_whitespace(alt);
                        if !clean_alt.is_empty() {
                            push_collapsed_inline_text(out, &clean_alt);
                        }
                    }
                }
                "ul" => {
                    render_list(children, out, child_ctx, false);
                }
                "ol" => {
                    render_list(children, out, child_ctx, true);
                }
                "li" => {
                    // Orphan <li> outside <ul>/<ol>
                    let mut item_buf = String::new();
                    render_nodes(children, &mut item_buf, child_ctx);
                    let normalized = normalize_markdown_output(&item_buf);
                    if !normalized.is_empty() {
                        ensure_newline(out);
                        out.push_str("- ");
                        out.push_str(&normalized);
                        out.push('\n');
                    }
                }
                "table" => {
                    render_table(children, out, child_ctx);
                }
                "div" | "section" | "article" | "header" | "footer" | "main" | "nav" | "aside"
                | "figure" | "figcaption" | "address" | "dl" | "dt" | "dd" => {
                    let mut inner = String::new();
                    render_nodes(children, &mut inner, child_ctx);
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        ensure_newline(out);
                        out.push_str(trimmed);
                        ensure_newline(out);
                    }
                }
                _ => {
                    render_nodes(children, out, child_ctx);
                }
            }
        }
    }
}

fn render_inline_wrapper(
    children: &[Node],
    out: &mut String,
    ctx: RenderCtx,
    prefix: &str,
    suffix: &str,
) {
    let inner = render_inline_fragment(children, ctx);
    let leading_space = inner.starts_with(char::is_whitespace);
    let trailing_space = inner.ends_with(char::is_whitespace);
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return;
    }
    if leading_space && !out.is_empty() && !out.ends_with([' ', '\n', '\t', '(']) {
        out.push(' ');
    }
    out.push_str(prefix);
    out.push_str(trimmed);
    out.push_str(suffix);
    if trailing_space {
        out.push(' ');
    }
}

fn render_inline_fragment(children: &[Node], ctx: RenderCtx) -> String {
    let mut buf = String::new();
    render_nodes(children, &mut buf, ctx);
    buf
}

fn render_list(children: &[Node], out: &mut String, ctx: RenderCtx, ordered: bool) {
    let indent = "  ".repeat(ctx.list_depth);
    let item_ctx = RenderCtx {
        list_depth: ctx.list_depth + 1,
        ..ctx
    };

    let mut items_rendered = 0usize;
    let mut block_buf = String::new();

    for child in children {
        match child {
            Node::Element {
                tag,
                children: li_children,
                ..
            } if tag == "li" => {
                let mut item_text = String::new();
                render_nodes(li_children, &mut item_text, item_ctx);
                let normalized = normalize_markdown_output(&item_text);
                if normalized.is_empty() {
                    continue;
                }
                items_rendered += 1;
                let marker = if ordered {
                    format!("{items_rendered}. ")
                } else {
                    "- ".to_string()
                };
                let cont_indent = " ".repeat(indent.len() + marker.len());
                for (line_idx, line) in normalized.lines().enumerate() {
                    if line_idx == 0 {
                        block_buf.push_str(&indent);
                        block_buf.push_str(&marker);
                        block_buf.push_str(line);
                    } else if line.trim().is_empty() {
                        // keep clean line break
                    } else if line.starts_with(&indent)
                        && (line.trim_start().starts_with("- ")
                            || line
                                .trim_start()
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_digit()))
                    {
                        // Nested list line already indented by recursive call
                        block_buf.push_str(line);
                    } else {
                        block_buf.push_str(&cont_indent);
                        block_buf.push_str(line);
                    }
                    block_buf.push('\n');
                }
            }
            Node::Element {
                tag,
                children: nested_children,
                ..
            } if tag == "ul" || tag == "ol" => {
                render_list(nested_children, &mut block_buf, item_ctx, tag == "ol");
            }
            _ => {}
        }
    }

    if items_rendered > 0 {
        if ctx.list_depth == 0 {
            ensure_blank_line(out);
            out.push_str(block_buf.trim_end());
            ensure_blank_line(out);
        } else {
            ensure_newline(out);
            out.push_str(block_buf.trim_end());
            out.push('\n');
        }
    }
}

struct TableRow {
    cells: Vec<String>,
    is_header: bool,
}

fn render_table(children: &[Node], out: &mut String, ctx: RenderCtx) {
    // If this table contains nested tables, treat it as an email layout wrapper and flatten blocks.
    if contains_nested_table(children) {
        render_layout_table_cells(children, out, ctx);
        return;
    }

    let mut rows = Vec::new();
    collect_table_rows(children, &mut rows, ctx);
    rows.retain(|r| r.cells.iter().any(|c| !c.is_empty()));

    if rows.is_empty() {
        return;
    }

    let max_cols = rows.iter().map(|r| r.cells.len()).max().unwrap_or(0);
    let any_header = rows.iter().any(|r| r.is_header);

    // Single-column tables with no <th> are typically email layout wrappers.
    if max_cols <= 1 && !any_header {
        render_layout_table_cells(children, out, ctx);
        return;
    }

    ensure_blank_line(out);

    for (row_idx, row) in rows.iter().enumerate() {
        out.push('|');
        for col_idx in 0..max_cols {
            let cell = row
                .cells
                .get(col_idx)
                .map(String::as_str)
                .unwrap_or("")
                .replace('|', "\\|");
            out.push(' ');
            out.push_str(&cell);
            out.push_str(" |");
        }
        out.push('\n');

        if row_idx == 0 {
            out.push('|');
            for _ in 0..max_cols {
                out.push_str(" --- |");
            }
            out.push('\n');
        }
    }

    ensure_blank_line(out);
}

fn contains_nested_table(nodes: &[Node]) -> bool {
    for node in nodes {
        if let Node::Element { tag, children, .. } = node
            && (tag == "table" || contains_nested_table(children))
        {
            return true;
        }
    }
    false
}

fn render_layout_table_cells(nodes: &[Node], out: &mut String, ctx: RenderCtx) {
    for node in nodes {
        if let Node::Element { tag, children, .. } = node {
            match tag.as_str() {
                "thead" | "tbody" | "tfoot" | "tr" => {
                    render_layout_table_cells(children, out, ctx);
                }
                "td" | "th" => {
                    let mut buf = String::new();
                    render_nodes(children, &mut buf, ctx);
                    let trimmed = buf.trim();
                    if !trimmed.is_empty() {
                        ensure_newline(out);
                        out.push_str(trimmed);
                        ensure_newline(out);
                    }
                }
                _ => render_node(node, out, ctx),
            }
        }
    }
}

fn collect_table_rows(nodes: &[Node], rows: &mut Vec<TableRow>, ctx: RenderCtx) {
    for node in nodes {
        if let Node::Element { tag, children, .. } = node {
            match tag.as_str() {
                "thead" | "tbody" | "tfoot" => collect_table_rows(children, rows, ctx),
                "tr" => {
                    let mut cells = Vec::new();
                    let mut all_th = true;
                    let mut saw_cell = false;
                    for cell_node in children {
                        if let Node::Element {
                            tag: cell_tag,
                            children: cell_children,
                            ..
                        } = cell_node
                            && (cell_tag == "td" || cell_tag == "th")
                        {
                            saw_cell = true;
                            if cell_tag != "th" {
                                all_th = false;
                            }
                            let mut cell_buf = String::new();
                            render_nodes(cell_children, &mut cell_buf, ctx);
                            let cleaned = collapse_inline_whitespace(&cell_buf);
                            cells.push(cleaned);
                        }
                    }
                    if saw_cell {
                        rows.push(TableRow {
                            cells,
                            is_header: all_th,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_raw_text(nodes: &[Node]) -> String {
    let mut out = String::new();
    for node in nodes {
        match node {
            Node::Text(t) => out.push_str(t),
            Node::Element { tag, children, .. } => {
                if tag == "br" {
                    out.push('\n');
                } else {
                    out.push_str(&collect_raw_text(children));
                }
            }
        }
    }
    out
}

fn sanitize_href(raw: &str) -> Option<String> {
    // Strip BiDi overrides, invisible Unicode tag chars, and C0/C1 controls BEFORE
    // checking the scheme so downstream `sanitize_untrusted_text` cannot mutate an
    // obfuscated href like `java&#x202e;script:...` into `javascript:...` (mXSS).
    let sanitized = crate::mime::sanitize_untrusted_text(raw);
    let trimmed = sanitized.trim();
    if trimmed.is_empty() || trimmed == "#" {
        return None;
    }

    // Reject control characters (including CR/LF/TAB) anywhere in the URL.
    if trimmed.chars().any(char::is_control) {
        return None;
    }

    // Strict allowlist of safe schemes (case-insensitive).
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("https://")
        || lower.starts_with("http://")
        || lower.starts_with("mailto:"))
    {
        return None;
    }

    Some(trimmed.to_string())
}

fn push_collapsed_inline_text(out: &mut String, text: &str) {
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space && !out.is_empty() && !out.ends_with([' ', '\n', '\t', '(', '[']) {
                out.push(' ');
            }
            pending_space = false;
            out.push(ch);
        }
    }
    if pending_space && !out.is_empty() && !out.ends_with([' ', '\n', '\t']) {
        out.push(' ');
    }
}

fn collapse_inline_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn trim_trailing_spaces(out: &mut String) {
    while out.ends_with([' ', '\t']) {
        out.pop();
    }
}

fn ensure_newline(out: &mut String) {
    trim_trailing_spaces(out);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

fn ensure_blank_line(out: &mut String) {
    trim_trailing_spaces(out);
    if out.is_empty() {
        return;
    }
    if out.ends_with("\n\n") {
        return;
    }
    if out.ends_with('\n') {
        out.push('\n');
    } else {
        out.push_str("\n\n");
    }
}

fn normalize_markdown_output(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    let mut blank_run = 0usize;
    let mut in_code_fence = false;

    for line in normalized.lines() {
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with("```") || trimmed_start.starts_with("~~~~") {
            in_code_fence = !in_code_fence;
            blank_run = 0;
            lines.push(line.trim_end().to_string());
            continue;
        }

        if in_code_fence {
            lines.push(line.to_string());
            continue;
        }

        let clean_line = line.trim_end();
        if clean_line.is_empty() {
            if !lines.is_empty() && blank_run == 0 {
                lines.push(String::new());
            }
            blank_run += 1;
        } else {
            blank_run = 0;
            lines.push(clean_line.to_string());
        }
    }

    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_headings_paragraphs_emphasis_and_hr() {
        let html = r#"
            <html>
              <head><title>Ignored Title</title><style>body { color: red; }</style></head>
              <body>
                <!-- Hidden comment -->
                <h1>Monthly Report</h1>
                <h2>Summary</h2>
                <p>Revenue is <strong>up 24%</strong> and churn is <em>down</em>.</p>
                <hr/>
                <p>Line one<br>Line two</p>
                <script>alert('xss')</script>
                <noscript>Enable JS</noscript>
              </body>
            </html>
        "#;

        let md = html_to_markdown(html);
        assert!(md.contains("# Monthly Report"), "got:\n{md}");
        assert!(md.contains("## Summary"), "got:\n{md}");
        assert!(
            md.contains("Revenue is **up 24%** and churn is *down*."),
            "got:\n{md}"
        );
        assert!(md.contains("---"), "got:\n{md}");
        assert!(md.contains("Line one\nLine two"), "got:\n{md}");
        assert!(!md.contains("Ignored Title"));
        assert!(!md.contains("color: red"));
        assert!(!md.contains("Hidden comment"));
        assert!(!md.contains("alert('xss')"));
        assert!(!md.contains("Enable JS"));
    }

    #[test]
    fn converts_links_and_strips_javascript_urls() {
        let html = r#"
            <p>
              Visit <a href="https://example.com/invoice?id=42&amp;view=full">Invoice #42</a>,
              email <a href="mailto:billing@example.com">Billing</a>,
              or click <a href="javascript:alert(1)">Danger Link</a>
              and <a href="  JaVa&#10;ScRiPt:void(0)">Obfuscated</a>.
            </p>
        "#;

        let md = html_to_markdown(html);
        assert!(
            md.contains("[Invoice #42](https://example.com/invoice?id=42&view=full)"),
            "got:\n{md}"
        );
        assert!(
            md.contains("[Billing](mailto:billing@example.com)"),
            "got:\n{md}"
        );
        assert!(md.contains("Danger Link"), "got:\n{md}");
        assert!(md.contains("Obfuscated"), "got:\n{md}");
        assert!(!md.to_ascii_lowercase().contains("javascript:"));
    }

    #[test]
    fn converts_lists_blockquotes_and_code_blocks() {
        let html = r#"
            <ul>
              <li>First item</li>
              <li>Second item
                <ol>
                  <li>Sub one</li>
                  <li>Sub two</li>
                </ol>
              </li>
            </ul>
            <blockquote><p>Quoted wisdom</p><p>Second paragraph</p></blockquote>
            <p>Run <code>cargo test</code> or:</p>
            <pre><code>fn main() {
    println!("hi");
}</code></pre>
        "#;

        let md = html_to_markdown(html);
        assert!(md.contains("- First item"), "got:\n{md}");
        assert!(md.contains("- Second item"), "got:\n{md}");
        assert!(md.contains("  1. Sub one"), "got:\n{md}");
        assert!(md.contains("  2. Sub two"), "got:\n{md}");
        assert!(md.contains("> Quoted wisdom"), "got:\n{md}");
        assert!(md.contains("> Second paragraph"), "got:\n{md}");
        assert!(md.contains("Run `cargo test` or:"), "got:\n{md}");
        assert!(
            md.contains("```\nfn main() {\n    println!(\"hi\");\n}\n```"),
            "got:\n{md}"
        );
    }

    #[test]
    fn converts_data_tables_and_flattens_single_col_layout_tables() {
        let data_table = r#"
            <table>
              <thead><tr><th>Item</th><th>Qty</th><th>Price</th></tr></thead>
              <tbody>
                <tr><td>Widget</td><td>2</td><td>$19.99</td></tr>
                <tr><td>Cable</td><td>1</td><td>$5.00</td></tr>
              </tbody>
            </table>
        "#;
        let md = html_to_markdown(data_table);
        assert!(md.contains("| Item | Qty | Price |"), "got:\n{md}");
        assert!(md.contains("| --- | --- | --- |"), "got:\n{md}");
        assert!(md.contains("| Widget | 2 | $19.99 |"), "got:\n{md}");
        assert!(md.contains("| Cable | 1 | $5.00 |"), "got:\n{md}");

        let layout_table = r#"
            <table>
              <tr><td><h1>Newsletter</h1><p>Welcome aboard!</p></td></tr>
            </table>
        "#;
        let layout_md = html_to_markdown(layout_table);
        assert!(layout_md.contains("# Newsletter"), "got:\n{layout_md}");
        assert!(layout_md.contains("Welcome aboard!"), "got:\n{layout_md}");
        assert!(!layout_md.contains("| --- |"));
    }

    #[test]
    fn decodes_named_and_numeric_html_entities() {
        let html = "<p>Tom &amp; Jerry &lt;3 &quot;cheese&quot; &#39;ok&#39; &#x27;hex&#x27; A&nbsp;B &#65; &#x1F680;</p>";
        let md = html_to_markdown(html);
        assert_eq!(md, "Tom & Jerry <3 \"cheese\" 'ok' 'hex' A B A \u{1F680}");
    }

    #[test]
    fn select_body_falls_back_to_html_when_plain_is_empty_or_thin() {
        let rich_html = "<h1>Receipt</h1><p>Thank you for your order. <a href=\"https://shop.example/r/99\">View receipt</a> for $49.00.</p>";

        // Empty plain text
        let (body, from_html) = select_body_or_html_markdown("   \n ", Some(rich_html));
        assert!(from_html);
        assert!(body.contains("# Receipt"));
        assert!(body.contains("[View receipt](https://shop.example/r/99)"));

        // Thin stub plain text
        let (body2, from_html2) =
            select_body_or_html_markdown("Please view this email in HTML", Some(rich_html));
        assert!(from_html2);
        assert!(body2.contains("# Receipt"));

        // Substantial plain text should be kept as-is
        let real_plain = "Receipt: Thank you for your order #99 for $49.00. Visit https://shop.example/r/99 to download.";
        let (body3, from_html3) = select_body_or_html_markdown(real_plain, Some(rich_html));
        assert!(!from_html3);
        assert_eq!(body3, real_plain);
    }

    #[test]
    fn sanitize_href_blocks_bidi_mxss_and_enforces_scheme_allowlist() {
        let html = concat!(
            r#"<a href="java&#x202e;script:alert(1)">BiDi XSS</a> "#,
            r#"<a href="java&#xE0001;script:alert(2)">Tag XSS</a> "#,
            r#"<a href="data:text/html,<script>alert(3)</script>">Data URI</a> "#,
            r#"<a href="vbscript:msgbox(1)">VBS</a> "#,
            r#"<a href="ftp://files.example.com/a">FTP</a> "#,
            r#"<a href="http://example.com/ok">HTTP</a> "#,
            r#"<a href="https://example.com/ok">HTTPS</a> "#,
            r#"<a href="mailto:user@example.com">Mailto</a>"#
        );

        let md = html_to_markdown(html);
        let sanitized = crate::mime::sanitize_untrusted_text(&md);
        for output in [&md, &sanitized] {
            let lower = output.to_ascii_lowercase();
            assert!(
                !lower.contains("javascript:"),
                "leaked javascript in {output}"
            );
            assert!(!lower.contains("data:text"), "leaked data uri in {output}");
            assert!(!lower.contains("vbscript:"), "leaked vbscript in {output}");
            assert!(!lower.contains("ftp://"), "leaked ftp in {output}");
            assert!(output.contains("[HTTP](http://example.com/ok)"));
            assert!(output.contains("[HTTPS](https://example.com/ok)"));
            assert!(output.contains("[Mailto](mailto:user@example.com)"));
            assert!(output.contains("BiDi XSS"));
            assert!(output.contains("Tag XSS"));
        }
    }
}
