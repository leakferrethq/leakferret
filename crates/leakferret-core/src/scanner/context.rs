//! Extracts the line-context window the classifier sees.

/// Return up to `n` lines either side of the line at `idx`. Trailing
/// newlines and `\r`s are stripped so the context is reporter-safe.
pub fn context_window(lines: &[&str], idx: usize, n: usize) -> Vec<String> {
    let start = idx.saturating_sub(n);
    let end = (idx + n + 1).min(lines.len());
    lines[start..end]
        .iter()
        .map(|s| s.trim_end_matches('\n').trim_end_matches('\r').to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_centered_window() {
        let lines = vec!["a\n", "b\n", "c\n", "d\n", "e\n"];
        let win = context_window(&lines, 2, 1);
        assert_eq!(win, vec!["b", "c", "d"]);
    }

    #[test]
    fn clamps_at_start_and_end() {
        let lines = vec!["a\n", "b\n", "c\n"];
        assert_eq!(context_window(&lines, 0, 2), vec!["a", "b", "c"]);
        assert_eq!(context_window(&lines, 2, 2), vec!["a", "b", "c"]);
    }
}
