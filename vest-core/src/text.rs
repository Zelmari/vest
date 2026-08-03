//! Safe text utilities for untrusted / Unicode content.

/// Truncate to at most `max_chars` Unicode scalar values without panicking.
///
/// Unlike byte slicing (`&s[..n]`), this never splits a multibyte character.
pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Truncate and append an ellipsis marker when content was cut.
pub fn truncate_chars_with_marker(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    format!("{}…", truncate_chars(s, keep))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_ok() {
        assert_eq!(truncate_chars("hello", 3), "hel");
        assert_eq!(truncate_chars("hi", 10), "hi");
    }

    #[test]
    fn multibyte_no_panic() {
        let s = "你好世界";
        assert_eq!(truncate_chars(s, 2), "你好");
        let emoji = "a😀b";
        assert_eq!(truncate_chars(emoji, 2), "a😀");
    }

    #[test]
    fn marker() {
        let out = truncate_chars_with_marker("abcdef", 4);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 4);
    }
}
