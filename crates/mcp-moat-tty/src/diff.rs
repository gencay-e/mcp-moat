use similar::{ChangeTag, TextDiff};
use std::io;
use std::path::Path;

/// Renders a plain unified diff
pub fn render_diff(old_content: &str, new_content: &str, file_name: &str) -> String {
    let diff = TextDiff::from_lines(old_content, new_content);
    let mut output = String::new();

    output.push_str(&format!("--- a/{}\n", file_name));
    output.push_str(&format!("+++ b/{}\n", file_name));

    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        output.push_str(&format!("{}{}", sign, change));
    }

    output
}

/// Renders an ANSI-colored unified diff (Green for insert, Red for delete, Bold Cyan for header)
pub fn render_colored_diff(old_content: &str, new_content: &str, file_name: &str) -> String {
    let diff = TextDiff::from_lines(old_content, new_content);
    let mut output = String::new();

    output.push_str(&format!("\x1b[1;36m--- a/{}\x1b[0m\n", file_name));
    output.push_str(&format!("\x1b[1;36m+++ b/{}\x1b[0m\n", file_name));

    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => {
                output.push_str(&format!("\x1b[31m-{}\x1b[0m", change));
            }
            ChangeTag::Insert => {
                output.push_str(&format!("\x1b[32m+{}\x1b[0m", change));
            }
            ChangeTag::Equal => {
                output.push_str(&format!(" {}", change));
            }
        }
    }

    output
}

/// Computes a unified diff for a target file on disk against new proposed content.
/// If the file does not exist, treats old content as empty (brand-new file).
pub fn diff_for_file(path: &Path, new_content: &str) -> io::Result<String> {
    const MAX_DIFF_SIZE: u64 = 1024 * 1024; // 1 MB limit for interactive diffs

    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_DIFF_SIZE {
            return Ok(format!(
                "[Large file modification ({} bytes) - diff preview omitted for performance]",
                meta.len()
            ));
        }
    }

    if new_content.len() > MAX_DIFF_SIZE as usize {
        return Ok(format!(
            "[Large content payload ({} bytes) - diff preview omitted for performance]",
            new_content.len()
        ));
    }

    let old_content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("file");
    Ok(render_colored_diff(&old_content, new_content, file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_plain_diff() {
        let old = "line1\nline2\n";
        let new = "line1\nline2_modified\nline3\n";
        let diff = render_diff(old, new, "test.txt");

        assert!(diff.contains("--- a/test.txt"));
        assert!(diff.contains("+++ b/test.txt"));
        assert!(diff.contains("-line2"));
        assert!(diff.contains("+line2_modified"));
        assert!(diff.contains("+line3"));
    }

    #[test]
    fn test_render_colored_diff() {
        let old = "hello\n";
        let new = "world\n";
        let diff = render_colored_diff(old, new, "greeting.txt");

        assert!(diff.contains("\x1b[1;36m--- a/greeting.txt\x1b[0m"));
        assert!(diff.contains("\x1b[31m-hello"));
        assert!(diff.contains("\x1b[32m+world"));
    }

    #[test]
    fn test_diff_for_new_file() {
        let tmp = std::env::temp_dir().join(format!("moat_test_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let diff = diff_for_file(&tmp, "new content\n").unwrap();
        assert!(diff.contains("+new content"));
    }

    #[test]
    fn test_diff_large_payload_safety() {
        let tmp = std::env::temp_dir().join(format!("moat_test_large_{}.txt", std::process::id()));
        let huge_content = "A".repeat(1024 * 1024 + 100);
        let diff = diff_for_file(&tmp, &huge_content).unwrap();
        assert!(diff.contains("Large content payload"));
    }
}
