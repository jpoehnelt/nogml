//! RFC 5256 `SORT` and `THREAD` (`REFERENCES`, `ORDEREDSUBJECT`) parsing,
//! base-subject extraction, sorting, threading, and response tree formatting.

use std::collections::{HashMap, HashSet};

use mail_parser::MessageParser;

use crate::{
    error::{AppError, AppResult},
    imap::parser::ImapArg,
    mime::normalize_message_id,
    storage::StoredMessage,
};

/// RFC 5256 Section 3 sort key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKeyKind {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
}

/// One sort criterion (`[REVERSE] <sort-key>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortCriterion {
    pub kind: SortKeyKind,
    pub reverse: bool,
}

/// RFC 5256 `THREAD` algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadAlgorithm {
    References,
    OrderedSubject,
}

/// Returns `true` if `charset` is supported by `SEARCH`, `SORT`, and `THREAD`.
pub fn is_supported_charset(charset: &str) -> bool {
    matches!(
        charset.to_ascii_uppercase().as_str(),
        "UTF-8" | "UTF8" | "US-ASCII" | "ASCII"
    )
}

/// Parse an RFC 5256 parenthesized sort program, e.g. `(REVERSE DATE SUBJECT)`.
pub fn parse_sort_criteria(list: &[ImapArg]) -> AppResult<Vec<SortCriterion>> {
    if list.is_empty() {
        return Err(AppError::BadRequest(
            "SORT criteria list must not be empty".to_string(),
        ));
    }
    let mut criteria = Vec::new();
    let mut reverse = false;
    for arg in list {
        let tok = arg
            .as_str_lossy()
            .ok_or_else(|| AppError::BadRequest("Invalid SORT key".to_string()))?;
        match tok.to_ascii_uppercase().as_str() {
            "REVERSE" => {
                if reverse {
                    return Err(AppError::BadRequest(
                        "Duplicate REVERSE in SORT criteria".to_string(),
                    ));
                }
                reverse = true;
            }
            "ARRIVAL" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::Arrival,
                    reverse,
                });
                reverse = false;
            }
            "CC" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::Cc,
                    reverse,
                });
                reverse = false;
            }
            "DATE" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::Date,
                    reverse,
                });
                reverse = false;
            }
            "FROM" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::From,
                    reverse,
                });
                reverse = false;
            }
            "SIZE" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::Size,
                    reverse,
                });
                reverse = false;
            }
            "SUBJECT" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::Subject,
                    reverse,
                });
                reverse = false;
            }
            "TO" => {
                criteria.push(SortCriterion {
                    kind: SortKeyKind::To,
                    reverse,
                });
                reverse = false;
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported SORT key: {other}"
                )));
            }
        }
    }
    if reverse {
        return Err(AppError::BadRequest(
            "REVERSE must be followed by a SORT key".to_string(),
        ));
    }
    Ok(criteria)
}

/// Returns `true` if any criterion requires loading the full [`StoredMessage`].
pub fn sort_criteria_needs_full_message(criteria: &[SortCriterion]) -> bool {
    criteria.iter().any(|c| {
        matches!(
            c.kind,
            SortKeyKind::Cc
                | SortKeyKind::Date
                | SortKeyKind::From
                | SortKeyKind::Subject
                | SortKeyKind::To
        )
    })
}

/// Returns `true` if any criterion inspects raw RFC 2822 bytes (for `Date:` header).
pub fn sort_criteria_needs_raw_rfc2822(criteria: &[SortCriterion]) -> bool {
    criteria.iter().any(|c| matches!(c.kind, SortKeyKind::Date))
}

/// Parse a `THREAD` algorithm name (`REFERENCES` or `ORDEREDSUBJECT`).
pub fn parse_thread_algorithm(raw: &str) -> AppResult<ThreadAlgorithm> {
    match raw.to_ascii_uppercase().as_str() {
        "REFERENCES" => Ok(ThreadAlgorithm::References),
        "ORDEREDSUBJECT" => Ok(ThreadAlgorithm::OrderedSubject),
        other => Err(AppError::BadRequest(format!(
            "Unsupported THREAD algorithm: {other}"
        ))),
    }
}

/// Extract RFC 5256 Section 2.1 base subject (lowercased) and whether any
/// `Re:`/`Fw:`/`Fwd:`/`(fwd)` reply or forward marker was stripped.
pub fn extract_base_subject_with_flag(raw: &str) -> (String, bool) {
    // Step 1: Collapse runs of whitespace to single spaces and trim.
    let mut s: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut had_refwd = false;

    loop {
        // Steps 2-5: Strip trailing (fwd) and leading leaders/blobs until stable.
        loop {
            let before = s.clone();

            // Step 2: Remove trailing "(fwd)" (case-insensitive) and whitespace.
            loop {
                let trimmed = s.trim_end();
                if trimmed.len() >= 5 && trimmed[trimmed.len() - 5..].eq_ignore_ascii_case("(fwd)")
                {
                    s = trimmed[..trimmed.len() - 5].trim_end().to_string();
                    had_refwd = true;
                } else {
                    if trimmed.len() != s.len() {
                        s = trimmed.to_string();
                    }
                    break;
                }
            }

            // Step 3: Remove subj-leader = (*subj-blob subj-refwd) / WSP
            loop {
                let trimmed = s.trim_start();
                if trimmed.len() != s.len() {
                    s = trimmed.to_string();
                }
                if let Some(rest) = strip_subj_leader(&s) {
                    s = rest.trim_start().to_string();
                    had_refwd = true;
                } else {
                    break;
                }
            }

            // Step 4: Remove leading [blob] if it is not the entire remaining subject.
            if let Some(rest) = strip_subj_blob(&s) {
                let rest_trimmed = rest.trim_start();
                if !rest_trimmed.is_empty() {
                    s = rest_trimmed.to_string();
                }
            }

            if s == before {
                break;
            }
        }

        // Step 6: If subject begins with "[fwd:" and ends with "]", strip wrapper and repeat.
        let trimmed = s.trim();
        if trimmed.len() >= 6
            && trimmed[..5].eq_ignore_ascii_case("[fwd:")
            && trimmed.ends_with(']')
        {
            s = trimmed[5..trimmed.len() - 1].trim().to_string();
            had_refwd = true;
            continue;
        }
        break;
    }

    (s.trim().to_lowercase(), had_refwd)
}

/// Extract RFC 5256 Section 2.1 base subject (lowercased).
pub fn extract_base_subject(raw: &str) -> String {
    extract_base_subject_with_flag(raw).0
}

/// Strip one `[blob]` (`'['` + non-bracket chars + `']'` + optional spaces).
fn strip_subj_blob(s: &str) -> Option<&str> {
    let rest = s.strip_prefix('[')?;
    let bytes = rest.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'[' {
            return None;
        }
        if b == b']' {
            return Some(&rest[i + 1..]);
        }
    }
    None
}

/// Strip `*subj-blob subj-refwd` where `subj-refwd = ("re" / "fw" / "fwd") *WSP [subj-blob] ":"`.
fn strip_subj_leader(s: &str) -> Option<&str> {
    let mut cur = s;
    while let Some(after_blob) = strip_subj_blob(cur) {
        cur = after_blob.trim_start();
    }
    let lower = cur.to_ascii_lowercase();
    let after_kw = if lower.starts_with("fwd") {
        &cur[3..]
    } else if lower.starts_with("re") || lower.starts_with("fw") {
        &cur[2..]
    } else {
        return None;
    };
    let mut after_kw = after_kw.trim_start();
    if let Some(after_blob) = strip_subj_blob(after_kw) {
        after_kw = after_blob.trim_start();
    }
    after_kw.strip_prefix(':')
}

/// Extract RFC 5256 Section 2.2 first `addr-mailbox` (local-part before `@`), lowercased.
pub fn extract_first_mailbox(raw_addr: &str) -> String {
    let trimmed = raw_addr.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Prefer the first angle-bracketed addr-spec if present.
    let addr_spec = if let Some(lt) = trimmed.find('<')
        && let Some(gt) = trimmed[lt + 1..].find('>')
    {
        trimmed[lt + 1..lt + 1 + gt].trim()
    } else {
        trimmed.split(',').next().unwrap_or(trimmed).trim()
    };
    let local = addr_spec.split('@').next().unwrap_or(addr_spec).trim();
    local.trim_matches('"').to_ascii_lowercase()
}

/// Extract sent `Date:` timestamp in epoch milliseconds from raw RFC 2822 bytes,
/// falling back to `fallback_internal_ms` per RFC 5256 Section 2.2.
pub fn message_sent_date_ms(msg: Option<&StoredMessage>, fallback_internal_ms: i64) -> i64 {
    let Some(m) = msg else {
        return fallback_internal_ms;
    };
    if m.raw_rfc2822.is_empty() {
        return fallback_internal_ms;
    }
    let Some(parsed) = MessageParser::new().parse(&m.raw_rfc2822) else {
        return fallback_internal_ms;
    };
    let Some(dt) = parsed.date() else {
        return fallback_internal_ms;
    };
    dt.to_timestamp().saturating_mul(1000)
}

/// Extract ordered, deduplicated normalized Message-IDs from `References` and `In-Reply-To`.
pub fn extract_references_list(msg: &StoredMessage) -> Vec<String> {
    let mut refs = Vec::new();
    let mut seen = HashSet::new();
    let self_id = msg
        .rfc822_message_id
        .as_deref()
        .and_then(normalize_message_id);

    let mut push_from_header = |raw: &str| {
        let mut rest = raw;
        while let Some(lt) = rest.find('<') {
            let after_lt = &rest[lt..];
            let Some(gt) = after_lt.find('>') else {
                break;
            };
            let token = &after_lt[..=gt];
            if let Some(norm) = normalize_message_id(token)
                && self_id.as_deref() != Some(norm.as_str())
                && seen.insert(norm.clone())
            {
                refs.push(norm);
            }
            rest = &after_lt[gt + 1..];
        }
    };

    if let Some(ref raw_refs) = msg.references_header {
        push_from_header(raw_refs);
    }
    if let Some(ref irt) = msg.in_reply_to {
        if irt.contains('<') {
            push_from_header(irt);
        } else if let Some(norm) = normalize_message_id(irt) {
            push_from_header(&norm);
        }
    }

    // Fallback: parse from raw RFC 2822 bytes if stored columns were empty.
    if refs.is_empty()
        && !msg.raw_rfc2822.is_empty()
        && let Some(parsed) = MessageParser::new().parse(&msg.raw_rfc2822)
    {
        if let Some(ref_list) = parsed.references() {
            for raw_ref in ref_list.iter() {
                if let Some(norm) = normalize_message_id(raw_ref)
                    && self_id.as_deref() != Some(norm.as_str())
                    && seen.insert(norm.clone())
                {
                    refs.push(norm);
                }
            }
        }
        if let Some(irt) = parsed.in_reply_to().and_then(|l| l.first())
            && let Some(norm) = normalize_message_id(irt)
            && self_id.as_deref() != Some(norm.as_str())
            && seen.insert(norm.clone())
        {
            refs.push(norm);
        }
    }

    refs
}

/// Metadata required to sort one matched message.
#[derive(Debug, Clone)]
pub struct SortMessageItem {
    /// Output identifier (`uid` for `UID SORT`, `seq` for `SORT`).
    pub out_id: u32,
    /// Stable 1-based sequence number for deterministic tie-breaking.
    pub seq: u32,
    pub internal_date_ms: i64,
    pub sent_date_ms: i64,
    pub size: usize,
    pub from_mailbox: String,
    pub to_mailbox: String,
    pub cc_mailbox: String,
    pub base_subject: String,
}

/// Sort matched messages according to RFC 5256 `criteria` and return ordered output IDs.
pub fn sort_messages(mut items: Vec<SortMessageItem>, criteria: &[SortCriterion]) -> Vec<u32> {
    items.sort_by(|a, b| {
        for crit in criteria {
            let ord = match crit.kind {
                SortKeyKind::Arrival => a.internal_date_ms.cmp(&b.internal_date_ms),
                SortKeyKind::Cc => a.cc_mailbox.cmp(&b.cc_mailbox),
                SortKeyKind::Date => a.sent_date_ms.cmp(&b.sent_date_ms),
                SortKeyKind::From => a.from_mailbox.cmp(&b.from_mailbox),
                SortKeyKind::Size => a.size.cmp(&b.size),
                SortKeyKind::Subject => a.base_subject.cmp(&b.base_subject),
                SortKeyKind::To => a.to_mailbox.cmp(&b.to_mailbox),
            };
            let ord = if crit.reverse { ord.reverse() } else { ord };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        a.seq.cmp(&b.seq)
    });
    items.into_iter().map(|i| i.out_id).collect()
}

/// Metadata required to thread one matched message.
#[derive(Debug, Clone)]
pub struct ThreadMessageItem {
    /// Output identifier (`uid` for `UID THREAD`, `seq` for `THREAD`).
    pub out_id: u32,
    pub seq: u32,
    pub sent_date_ms: i64,
    pub base_subject: String,
    pub is_reply_or_fwd: bool,
    pub message_id: Option<String>,
    pub references: Vec<String>,
    pub thread_id: String,
}

/// Format matched messages using RFC 5256 `ORDEREDSUBJECT` threading.
pub fn thread_ordered_subject(items: &[ThreadMessageItem]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut groups: HashMap<&str, Vec<&ThreadMessageItem>> = HashMap::new();
    for item in items {
        groups
            .entry(item.base_subject.as_str())
            .or_default()
            .push(item);
    }

    let mut ordered_groups: Vec<Vec<&ThreadMessageItem>> = groups
        .into_values()
        .map(|mut g| {
            g.sort_by_key(|i| (i.sent_date_ms, i.seq));
            g
        })
        .collect();
    ordered_groups.sort_by_key(|g| (g[0].sent_date_ms, g[0].seq));

    let mut out = String::new();
    for group in ordered_groups {
        out.push('(');
        for (idx, item) in group.iter().enumerate() {
            if idx > 0 {
                out.push(' ');
            }
            out.push_str(&item.out_id.to_string());
        }
        out.push(')');
    }
    out
}

#[derive(Debug, Default)]
struct Container {
    item_idx: Option<usize>,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// Format matched messages using RFC 5256 `REFERENCES` threading.
pub fn thread_references(items: &[ThreadMessageItem]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let mut containers: Vec<Container> = Vec::new();
    let mut id_table: HashMap<String, usize> = HashMap::new();

    let get_or_create = |containers: &mut Vec<Container>,
                         id_table: &mut HashMap<String, usize>,
                         id: &str|
     -> usize {
        if let Some(&idx) = id_table.get(id) {
            return idx;
        }
        let idx = containers.len();
        containers.push(Container::default());
        id_table.insert(id.to_string(), idx);
        idx
    };

    // Step 1: Build parent/child links from Message-ID, References, and In-Reply-To.
    for (item_idx, item) in items.iter().enumerate() {
        let c_idx = if let Some(ref mid) = item.message_id {
            if let Some(&existing) = id_table.get(mid) {
                if containers[existing].item_idx.is_none() {
                    containers[existing].item_idx = Some(item_idx);
                    existing
                } else {
                    // Duplicate Message-ID: create a separate container so no message is dropped.
                    let fresh = containers.len();
                    containers.push(Container {
                        item_idx: Some(item_idx),
                        parent: None,
                        children: Vec::new(),
                    });
                    fresh
                }
            } else {
                let idx = get_or_create(&mut containers, &mut id_table, mid);
                containers[idx].item_idx = Some(item_idx);
                idx
            }
        } else {
            let fresh = containers.len();
            containers.push(Container {
                item_idx: Some(item_idx),
                parent: None,
                children: Vec::new(),
            });
            fresh
        };

        // Link consecutive references.
        for pair in item.references.windows(2) {
            let p_idx = get_or_create(&mut containers, &mut id_table, &pair[0]);
            let ch_idx = get_or_create(&mut containers, &mut id_table, &pair[1]);
            if p_idx != ch_idx
                && containers[ch_idx].parent.is_none()
                && !is_ancestor(&containers, ch_idx, p_idx)
            {
                containers[ch_idx].parent = Some(p_idx);
                if !containers[p_idx].children.contains(&ch_idx) {
                    containers[p_idx].children.push(ch_idx);
                }
            }
        }

        // Link the message itself to its immediate parent reference (if any).
        if let Some(last_ref) = item.references.last() {
            let p_idx = get_or_create(&mut containers, &mut id_table, last_ref);
            if p_idx != c_idx && !is_ancestor(&containers, c_idx, p_idx) {
                if let Some(old_parent) = containers[c_idx].parent.take() {
                    containers[old_parent].children.retain(|&ch| ch != c_idx);
                }
                containers[c_idx].parent = Some(p_idx);
                if !containers[p_idx].children.contains(&c_idx) {
                    containers[p_idx].children.push(c_idx);
                }
            }
        }
    }

    // Step 2: Gather root set.
    let initial_roots: Vec<usize> = (0..containers.len())
        .filter(|&i| containers[i].parent.is_none())
        .collect();

    // Step 3: Prune empty (dummy) containers recursively.
    let mut roots: Vec<usize> = Vec::new();
    for r in initial_roots {
        prune_children(&mut containers, r);
        if containers[r].item_idx.is_none() {
            match containers[r].children.len() {
                0 => {}
                1 => {
                    let only = containers[r].children.pop().unwrap();
                    containers[only].parent = None;
                    roots.push(only);
                }
                _ => {
                    roots.push(r);
                }
            }
        } else {
            roots.push(r);
        }
    }

    // Step 4: Sort roots and children by date so subject gathering is deterministic.
    for &r in &roots {
        sort_children_recursive(&mut containers, items, r);
    }
    roots.sort_by_key(|&r| subtree_sort_key(&containers, items, r));

    // Step 5: Gather roots with the same non-empty base subject (RFC 5256 Section 3.7 step 5).
    let mut subject_winners: HashMap<String, usize> = HashMap::new();
    for &r in &roots {
        let Some((subj, is_refwd)) = root_subject_info(&containers, items, r) else {
            continue;
        };
        if subj.is_empty() {
            continue;
        }
        match subject_winners.get(&subj).copied() {
            None => {
                subject_winners.insert(subj, r);
            }
            Some(prev) => {
                let prev_dummy = containers[prev].item_idx.is_none();
                let r_dummy = containers[r].item_idx.is_none();
                let prev_refwd = root_subject_info(&containers, items, prev)
                    .map(|(_, f)| f)
                    .unwrap_or(false);
                // Prefer dummy container, or non-Re/Fwd container over Re/Fwd container.
                let replace = (r_dummy && !prev_dummy)
                    || (!prev_dummy && !r_dummy && prev_refwd && !is_refwd);
                if replace {
                    subject_winners.insert(subj, r);
                }
            }
        }
    }

    let mut merged_roots: Vec<usize> = Vec::new();
    let mut consumed: HashSet<usize> = HashSet::new();
    for &r in &roots {
        if consumed.contains(&r) {
            continue;
        }
        let Some((subj, r_refwd)) = root_subject_info(&containers, items, r) else {
            merged_roots.push(r);
            continue;
        };
        if subj.is_empty() {
            merged_roots.push(r);
            continue;
        }
        let winner = match subject_winners.get(&subj).copied() {
            Some(w) => w,
            None => {
                merged_roots.push(r);
                continue;
            }
        };
        if winner == r {
            merged_roots.push(r);
            continue;
        }

        // Merge `r` into `winner`.
        consumed.insert(r);
        let winner_dummy = containers[winner].item_idx.is_none();
        let r_dummy = containers[r].item_idx.is_none();
        let winner_refwd = root_subject_info(&containers, items, winner)
            .map(|(_, f)| f)
            .unwrap_or(false);

        if winner_dummy && r_dummy {
            let moved = std::mem::take(&mut containers[r].children);
            for ch in moved {
                containers[ch].parent = Some(winner);
                containers[winner].children.push(ch);
            }
        } else if winner_dummy {
            containers[r].parent = Some(winner);
            containers[winner].children.push(r);
        } else if !winner_refwd && !r_refwd && !r_dummy {
            // Both are original (non-Re/Fwd) messages with the same subject:
            // group both under a new dummy root container.
            let dummy_idx = containers.len();
            containers.push(Container {
                item_idx: None,
                parent: None,
                children: vec![winner, r],
            });
            containers[winner].parent = Some(dummy_idx);
            containers[r].parent = Some(dummy_idx);
            if let Some(pos) = merged_roots.iter().position(|&x| x == winner) {
                merged_roots[pos] = dummy_idx;
            }
            subject_winners.insert(subj, dummy_idx);
        } else {
            containers[r].parent = Some(winner);
            containers[winner].children.push(r);
        }
    }

    // Step 5b: Merge remaining distinct roots that share the same explicit `thread_id`
    // (covers Gmail threads whose messages omit RFC 2822 References/In-Reply-To headers).
    let mut thread_winners: HashMap<String, usize> = HashMap::new();
    let mut final_roots: Vec<usize> = Vec::new();
    for r in merged_roots {
        let Some(tid) = root_thread_id(&containers, items, r) else {
            final_roots.push(r);
            continue;
        };
        if tid.is_empty() {
            final_roots.push(r);
            continue;
        }
        if let Some(&winner) = thread_winners.get(&tid) {
            if winner != r {
                if containers[r].item_idx.is_none() {
                    let moved = std::mem::take(&mut containers[r].children);
                    for ch in moved {
                        containers[ch].parent = Some(winner);
                        containers[winner].children.push(ch);
                    }
                } else {
                    containers[r].parent = Some(winner);
                    containers[winner].children.push(r);
                }
            }
        } else {
            thread_winners.insert(tid, r);
            final_roots.push(r);
        }
    }

    // Step 6: Sort children at every level and sort final roots by sent date ascending.
    for &r in &final_roots {
        sort_children_recursive(&mut containers, items, r);
    }
    final_roots.sort_by_key(|&r| subtree_sort_key(&containers, items, r));

    // Step 7: Format according to RFC 5256 Section 4 ABNF.
    let mut out = String::new();
    for r in final_roots {
        format_thread_list(&containers, items, r, &mut out);
    }
    out
}

fn is_ancestor(containers: &[Container], candidate_ancestor: usize, mut node: usize) -> bool {
    let mut steps = 0usize;
    while let Some(parent) = containers[node].parent {
        if parent == candidate_ancestor {
            return true;
        }
        node = parent;
        steps += 1;
        if steps > containers.len() {
            return true;
        }
    }
    false
}

fn prune_children(containers: &mut [Container], c_idx: usize) {
    let children = std::mem::take(&mut containers[c_idx].children);
    let mut kept = Vec::with_capacity(children.len());
    for ch in children {
        prune_children(containers, ch);
        if containers[ch].item_idx.is_none() {
            let grandchildren = std::mem::take(&mut containers[ch].children);
            for g in grandchildren {
                containers[g].parent = Some(c_idx);
                kept.push(g);
            }
        } else {
            kept.push(ch);
        }
    }
    containers[c_idx].children = kept;
}

fn subtree_sort_key(
    containers: &[Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
) -> (i64, u32) {
    if let Some(idx) = containers[c_idx].item_idx {
        let item = &items[idx];
        return (item.sent_date_ms, item.seq);
    }
    containers[c_idx]
        .children
        .iter()
        .map(|&ch| subtree_sort_key(containers, items, ch))
        .min()
        .unwrap_or((i64::MAX, u32::MAX))
}

fn sort_children_recursive(
    containers: &mut [Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
) {
    let mut children = std::mem::take(&mut containers[c_idx].children);
    for &ch in &children {
        sort_children_recursive(containers, items, ch);
    }
    children.sort_by_key(|&ch| subtree_sort_key(containers, items, ch));
    containers[c_idx].children = children;
}

fn root_subject_info(
    containers: &[Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
) -> Option<(String, bool)> {
    if let Some(idx) = containers[c_idx].item_idx {
        let item = &items[idx];
        return Some((item.base_subject.clone(), item.is_reply_or_fwd));
    }
    for &ch in &containers[c_idx].children {
        if let Some(info) = root_subject_info(containers, items, ch) {
            return Some(info);
        }
    }
    None
}

fn root_thread_id(
    containers: &[Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
) -> Option<String> {
    if let Some(idx) = containers[c_idx].item_idx {
        return Some(items[idx].thread_id.clone());
    }
    for &ch in &containers[c_idx].children {
        if let Some(tid) = root_thread_id(containers, items, ch) {
            return Some(tid);
        }
    }
    None
}

fn format_thread_list(
    containers: &[Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
    out: &mut String,
) {
    out.push('(');
    format_thread_members(containers, items, c_idx, out);
    out.push(')');
}

fn format_thread_members(
    containers: &[Container],
    items: &[ThreadMessageItem],
    c_idx: usize,
    out: &mut String,
) {
    let c = &containers[c_idx];
    if let Some(idx) = c.item_idx {
        out.push_str(&items[idx].out_id.to_string());
        match c.children.len() {
            0 => {}
            1 => {
                out.push(' ');
                format_thread_members(containers, items, c.children[0], out);
            }
            _ => {
                out.push(' ');
                for &child in &c.children {
                    format_thread_list(containers, items, child, out);
                }
            }
        }
    } else {
        for &child in &c.children {
            format_thread_list(containers, items, child, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_subject_extraction_follows_rfc5256() {
        assert_eq!(
            extract_base_subject("Re: Quarterly Budget"),
            "quarterly budget"
        );
        assert_eq!(
            extract_base_subject("Re: Fwd: [finance] Re[2]: Quarterly Budget (fwd)"),
            "quarterly budget"
        );
        assert_eq!(
            extract_base_subject("[fwd: Re: Hello World]"),
            "hello world"
        );
        assert_eq!(extract_base_subject("[only-blob]"), "[only-blob]");
        assert_eq!(extract_base_subject("  Hello   \t  World  "), "hello world");
        let (_, is_re) = extract_base_subject_with_flag("Re: Topic");
        assert!(is_re);
        let (_, not_re) = extract_base_subject_with_flag("Topic");
        assert!(!not_re);
    }

    #[test]
    fn first_mailbox_extraction_ignores_display_name() {
        assert_eq!(
            extract_first_mailbox(r#""Zoe" <alice@example.com>"#),
            "alice"
        );
        assert_eq!(extract_first_mailbox("Bob <BOB@Example.org>"), "bob");
        assert_eq!(
            extract_first_mailbox("carol@example.com, dave@example.com"),
            "carol"
        );
        assert_eq!(extract_first_mailbox(""), "");
    }

    #[test]
    fn thread_references_builds_nested_branches_and_dummy_roots() {
        // Thread 1: 1 -> (2 -> 3) and (4)
        // Thread 2: missing parent <ghost> -> (5) and (6)
        let items = vec![
            ThreadMessageItem {
                out_id: 10,
                seq: 1,
                sent_date_ms: 1000,
                base_subject: "alpha".to_string(),
                is_reply_or_fwd: false,
                message_id: Some("<m1@ex>".to_string()),
                references: vec![],
                thread_id: "t1".to_string(),
            },
            ThreadMessageItem {
                out_id: 20,
                seq: 2,
                sent_date_ms: 2000,
                base_subject: "alpha".to_string(),
                is_reply_or_fwd: true,
                message_id: Some("<m2@ex>".to_string()),
                references: vec!["<m1@ex>".to_string()],
                thread_id: "t1".to_string(),
            },
            ThreadMessageItem {
                out_id: 30,
                seq: 3,
                sent_date_ms: 3000,
                base_subject: "alpha".to_string(),
                is_reply_or_fwd: true,
                message_id: Some("<m3@ex>".to_string()),
                references: vec!["<m1@ex>".to_string(), "<m2@ex>".to_string()],
                thread_id: "t1".to_string(),
            },
            ThreadMessageItem {
                out_id: 40,
                seq: 4,
                sent_date_ms: 4000,
                base_subject: "alpha".to_string(),
                is_reply_or_fwd: true,
                message_id: Some("<m4@ex>".to_string()),
                references: vec!["<m1@ex>".to_string()],
                thread_id: "t1".to_string(),
            },
            ThreadMessageItem {
                out_id: 50,
                seq: 5,
                sent_date_ms: 5000,
                base_subject: "orphan".to_string(),
                is_reply_or_fwd: true,
                message_id: Some("<m5@ex>".to_string()),
                references: vec!["<ghost@ex>".to_string()],
                thread_id: "t2".to_string(),
            },
            ThreadMessageItem {
                out_id: 60,
                seq: 6,
                sent_date_ms: 6000,
                base_subject: "orphan".to_string(),
                is_reply_or_fwd: true,
                message_id: Some("<m6@ex>".to_string()),
                references: vec!["<ghost@ex>".to_string()],
                thread_id: "t3".to_string(),
            },
        ];

        assert_eq!(thread_references(&items), "(10 (20 30)(40))((50)(60))");
        assert_eq!(thread_ordered_subject(&items), "(10 20 30 40)(50 60)");
    }
}
