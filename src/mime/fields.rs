//! Gmail & AI `?fields=` partial-response JSON projection parser and evaluator.
//!
//! Supports:
//! - Comma `,` for multiple fields at the same level (`id,threadId,nextPageToken`)
//! - Slash `/` and dot `.` for nested paths (`payload/headers`, `messages.text`)
//! - Parentheses `(...)` for sub-selections on objects and arrays
//!   (`messages(id,threadId),nextPageToken`, `messages(id,payload(headers,mimeType))`)
//! - Wildcard `*` to select all fields at a node (`*`, `payload/*`, `messages(*)`)
//! - Missing fields are silently omitted; empty mask returns the value unchanged.

use serde_json::{Map, Value};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Default)]
struct FieldNode {
    /// Whether all fields/contents at this node are selected (leaf field or `*`).
    select_all: bool,
    /// Named child selections in insertion order (merged by key).
    children: Vec<(String, FieldNode)>,
}

impl FieldNode {
    fn child_mut(&mut self, key: &str) -> &mut FieldNode {
        if let Some(pos) = self.children.iter().position(|(k, _)| k == key) {
            &mut self.children[pos].1
        } else {
            self.children.push((key.to_string(), FieldNode::default()));
            &mut self.children.last_mut().expect("just pushed").1
        }
    }

    fn merge_from(&mut self, other: FieldNode) {
        if other.select_all {
            self.select_all = true;
        }
        for (k, v) in other.children {
            self.child_mut(&k).merge_from(v);
        }
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn parse_root(&mut self) -> AppResult<FieldNode> {
        let mut root = FieldNode::default();
        self.parse_field_list(&mut root, false)?;
        self.skip_ws();
        if self.pos < self.input.len() {
            return Err(AppError::BadRequest(format!(
                "Unexpected trailing characters in fields mask at position {}: {:?}",
                self.pos,
                self.rest()
            )));
        }
        Ok(root)
    }

    fn parse_field_list(&mut self, target: &mut FieldNode, expect_rparen: bool) -> AppResult<()> {
        let mut parsed_any = false;
        loop {
            self.skip_ws();
            match self.peek() {
                None => {
                    if expect_rparen {
                        return Err(AppError::BadRequest(
                            "Unclosed '(' in fields mask".to_string(),
                        ));
                    }
                    if !parsed_any {
                        return Err(AppError::BadRequest(
                            "Empty selector in fields mask".to_string(),
                        ));
                    }
                    break;
                }
                Some(')') => {
                    if !expect_rparen {
                        return Err(AppError::BadRequest(format!(
                            "Unexpected ')' in fields mask at position {}",
                            self.pos
                        )));
                    }
                    if !parsed_any {
                        return Err(AppError::BadRequest(
                            "Empty sub-selection '()' in fields mask".to_string(),
                        ));
                    }
                    self.advance();
                    break;
                }
                Some('(') => {
                    // Allow root/grouped parenthesized list `(id,subject)` on top-level arrays/objects.
                    self.advance();
                    self.parse_field_list(target, true)?;
                    parsed_any = true;
                }
                Some(_) => {
                    self.parse_selector(target)?;
                    parsed_any = true;
                }
            }

            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.advance();
                    self.skip_ws();
                    // Reject trailing comma or empty segment like `a,,b` or `a,)`.
                    if matches!(self.peek(), None | Some(',') | Some(')')) {
                        return Err(AppError::BadRequest(format!(
                            "Empty field selector after ',' at position {}",
                            self.pos
                        )));
                    }
                }
                Some(')') if expect_rparen => {
                    self.advance();
                    break;
                }
                None if !expect_rparen => break,
                Some(ch) => {
                    return Err(AppError::BadRequest(format!(
                        "Unexpected character '{ch}' in fields mask at position {}",
                        self.pos
                    )));
                }
                None => {
                    return Err(AppError::BadRequest(
                        "Unclosed '(' in fields mask".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn parse_selector(&mut self, target: &mut FieldNode) -> AppResult<()> {
        let mut segments: Vec<String> = Vec::new();
        loop {
            self.skip_ws();
            let seg = self.parse_segment()?;
            segments.push(seg);

            self.skip_ws();
            if matches!(self.peek(), Some('/') | Some('.')) {
                self.advance();
                continue;
            }
            break;
        }

        // Check for optional `(...)` sub-selection.
        self.skip_ws();
        let sub_node = if self.peek() == Some('(') {
            self.advance();
            let mut node = FieldNode::default();
            self.parse_field_list(&mut node, true)?;
            Some(node)
        } else {
            None
        };

        // Insert path into `target`.
        let mut current = target;
        for (idx, seg) in segments.iter().enumerate() {
            let is_last = idx + 1 == segments.len();
            if seg == "*" {
                if let Some(ref sub) = sub_node
                    && is_last
                {
                    current.merge_from(sub.clone());
                } else {
                    current.select_all = true;
                }
                return Ok(());
            }
            current = current.child_mut(seg);
        }

        match sub_node {
            Some(sub) => current.merge_from(sub),
            None => current.select_all = true,
        }

        Ok(())
    }

    fn parse_segment(&mut self) -> AppResult<String> {
        self.skip_ws();
        if self.peek() == Some('*') {
            self.advance();
            return Ok("*".to_string());
        }

        let start = self.pos;
        while let Some(ch) = self.peek() {
            if matches!(ch, ',' | '/' | '.' | '(' | ')') || ch.is_whitespace() {
                break;
            }
            self.pos += ch.len_utf8();
        }

        if self.pos == start {
            return Err(AppError::BadRequest(format!(
                "Expected field name in fields mask at position {}",
                self.pos
            )));
        }

        Ok(self.input[start..self.pos].to_string())
    }
}

fn apply_node(value: Value, node: &FieldNode) -> Option<Value> {
    if node.select_all {
        return Some(value);
    }

    match value {
        Value::Object(mut obj) => {
            let mut out = Map::new();
            for (key, child_node) in &node.children {
                if let Some(child_val) = obj.remove(key)
                    && let Some(projected) = apply_node(child_val, child_node)
                {
                    out.insert(key.clone(), projected);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(Value::Object(out))
            }
        }
        Value::Array(items) => {
            let projected: Vec<Value> = items
                .into_iter()
                .filter_map(|item| apply_node(item, node))
                .collect();
            Some(Value::Array(projected))
        }
        // Primitive values cannot satisfy further child sub-selections.
        _ => None,
    }
}

/// Apply a Google/Gmail partial response `?fields=` mask or dot-notation projection to a JSON value.
///
/// Supports `,`, `/`, `.`, `(...)` on objects and arrays, and `*` wildcards.
/// Missing fields are silently omitted; empty mask returns `value` unchanged.
pub fn apply_fields_mask(value: Value, fields: &str) -> AppResult<Value> {
    let trimmed = fields.trim();
    if trimmed.is_empty() {
        return Ok(value);
    }

    let mut parser = Parser::new(trimmed);
    let root = parser.parse_root()?;

    if root.select_all {
        return Ok(value);
    }

    Ok(match apply_node(value, &root) {
        Some(v) => v,
        None => Value::Object(Map::new()),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn empty_and_wildcard_return_full_value() {
        let val = json!({ "id": "m1", "threadId": "t1", "snippet": "hi" });
        assert_eq!(apply_fields_mask(val.clone(), "").unwrap(), val);
        assert_eq!(apply_fields_mask(val.clone(), "   ").unwrap(), val);
        assert_eq!(apply_fields_mask(val.clone(), "*").unwrap(), val);
    }

    #[test]
    fn flat_and_nested_slash_and_dot_paths() {
        let val = json!({
            "id": "m1",
            "threadId": "t1",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    { "name": "From", "value": "alice@example.com" },
                    { "name": "Subject", "value": "Hello" }
                ],
                "body": { "size": 42, "data": "aGk" }
            }
        });

        assert_eq!(
            apply_fields_mask(val.clone(), "id,payload/mimeType,payload/body/size").unwrap(),
            json!({
                "id": "m1",
                "payload": {
                    "mimeType": "text/plain",
                    "body": { "size": 42 }
                }
            })
        );

        assert_eq!(
            apply_fields_mask(val.clone(), "id,payload.body.size").unwrap(),
            json!({
                "id": "m1",
                "payload": { "body": { "size": 42 } }
            })
        );

        assert_eq!(
            apply_fields_mask(val, "payload/*").unwrap(),
            json!({
                "payload": {
                    "mimeType": "text/plain",
                    "headers": [
                        { "name": "From", "value": "alice@example.com" },
                        { "name": "Subject", "value": "Hello" }
                    ],
                    "body": { "size": 42, "data": "aGk" }
                }
            })
        );
    }

    #[test]
    fn parentheses_on_arrays_and_nested_objects() {
        let val = json!({
            "messages": [
                {
                    "id": "m1",
                    "threadId": "t1",
                    "snippet": "first",
                    "payload": {
                        "mimeType": "text/plain",
                        "headers": [{ "name": "From", "value": "a@b.com" }]
                    }
                },
                {
                    "id": "m2",
                    "threadId": "t2",
                    "snippet": "second",
                    "payload": {
                        "mimeType": "text/html",
                        "headers": [{ "name": "From", "value": "c@d.com" }]
                    }
                }
            ],
            "nextPageToken": "tok123",
            "resultSizeEstimate": 2
        });

        let projected = apply_fields_mask(
            val.clone(),
            "messages(id,payload(mimeType,headers(name))),nextPageToken",
        )
        .unwrap();

        assert_eq!(
            projected,
            json!({
                "messages": [
                    {
                        "id": "m1",
                        "payload": {
                            "mimeType": "text/plain",
                            "headers": [{ "name": "From" }]
                        }
                    },
                    {
                        "id": "m2",
                        "payload": {
                            "mimeType": "text/html",
                            "headers": [{ "name": "From" }]
                        }
                    }
                ],
                "nextPageToken": "tok123"
            })
        );

        // Dot notation on array elements (AI `/v1` style)
        let dot_proj = apply_fields_mask(val, "messages.id,nextPageToken").unwrap();
        assert_eq!(
            dot_proj,
            json!({
                "messages": [{ "id": "m1" }, { "id": "m2" }],
                "nextPageToken": "tok123"
            })
        );
    }

    #[test]
    fn missing_fields_omitted_without_error() {
        let val = json!({ "id": "m1", "payload": { "mimeType": "text/plain" } });
        assert_eq!(
            apply_fields_mask(val.clone(), "id,nonexistent,payload/missing").unwrap(),
            json!({ "id": "m1" })
        );
        assert_eq!(
            apply_fields_mask(val, "totallyMissing").unwrap(),
            json!({})
        );
    }

    #[test]
    fn invalid_syntax_returns_bad_request() {
        let val = json!({ "id": "m1" });
        assert!(apply_fields_mask(val.clone(), "messages(id").is_err());
        assert!(apply_fields_mask(val.clone(), "messages)").is_err());
        assert!(apply_fields_mask(val.clone(), "id,,threadId").is_err());
        assert!(apply_fields_mask(val.clone(), "messages()").is_err());
        assert!(apply_fields_mask(val, "id,").is_err());
    }

    #[test]
    fn merges_split_selectors_and_handles_arrays_and_wildcards() {
        let val = json!({
            "messages": [
                { "id": "1", "threadId": "t1", "snippet": "s1" },
                { "id": "2", "threadId": "t2", "snippet": "s2" }
            ],
            "emptyList": []
        });

        assert_eq!(
            apply_fields_mask(val.clone(), "messages(id),messages(threadId),emptyList(id)").unwrap(),
            json!({
                "messages": [
                    { "id": "1", "threadId": "t1" },
                    { "id": "2", "threadId": "t2" }
                ],
                "emptyList": []
            })
        );

        assert_eq!(
            apply_fields_mask(val, "messages(*)").unwrap(),
            json!({
                "messages": [
                    { "id": "1", "threadId": "t1", "snippet": "s1" },
                    { "id": "2", "threadId": "t2", "snippet": "s2" }
                ]
            })
        );

        let top_array = json!([
            { "id": "a", "extra": 1 },
            { "id": "b", "extra": 2 }
        ]);
        assert_eq!(
            apply_fields_mask(top_array.clone(), "id").unwrap(),
            json!([{ "id": "a" }, { "id": "b" }])
        );
        assert_eq!(
            apply_fields_mask(top_array, "(id)").unwrap(),
            json!([{ "id": "a" }, { "id": "b" }])
        );
    }
}
