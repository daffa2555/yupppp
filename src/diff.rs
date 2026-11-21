use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct DiffLine {
    pub line_no: usize,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDiff {
    pub path: String,
    pub added: Vec<DiffLine>,
    pub removed: Vec<DiffLine>,
}

impl FileDiff {
    pub fn is_test_file(&self) -> bool {
        let lower = self.path.to_lowercase();
        lower.contains("/test/")
            || lower.contains("/tests/")
            || lower.contains("__tests__")
            || lower.starts_with("test_")
            || lower.starts_with("tests/")
            || lower.ends_with("_test.go")
            || lower.ends_with("_test.rs")
            || lower.ends_with(".test.ts")
            || lower.ends_with(".test.tsx")
            || lower.ends_with(".test.js")
            || lower.ends_with(".test.mjs")
            || lower.ends_with(".spec.ts")
            || lower.ends_with(".spec.js")
            || lower.contains("/test_")
    }
}

pub fn parse_unified_diff(raw: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    let mut old_line: usize = 0;
    let mut new_line: usize = 0;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            if let Some(prev) = current.take() {
                files.push(prev);
            }
            current = Some(FileDiff {
                path: rest.trim().to_string(),
                added: Vec::new(),
                removed: Vec::new(),
            });
            old_line = 0;
            new_line = 0;
            continue;
        }
        if line.starts_with("+++ /dev/null") {
            if let Some(prev) = current.take() {
                files.push(prev);
            }
            continue;
        }
        if line.starts_with("@@ ") {
            // Parse @@ -old_start[,count] +new_start[,count] @@
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                old_line = parts[1]
                    .trim_start_matches('-')
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                new_line = parts[2]
                    .trim_start_matches('+')
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
            }
            continue;
        }

        let Some(file) = current.as_mut() else {
            continue;
        };

        if let Some(added) = line.strip_prefix('+') {
            if !line.starts_with("+++") {
                file.added.push(DiffLine {
                    line_no: new_line,
                    content: added.to_string(),
                });
                new_line += 1;
            }
        } else if let Some(removed) = line.strip_prefix('-') {
            if !line.starts_with("---") {
                file.removed.push(DiffLine {
                    line_no: old_line,
                    content: removed.to_string(),
                });
                old_line += 1;
            }
        } else if line.starts_with(' ') {
            old_line += 1;
            new_line += 1;
        }
    }

    if let Some(last) = current {
        files.push(last);
    }
    files
}

/// Resolve the git base ref used to fetch pre-change file contents (`git show <base>:<file>`).
pub fn resolve_base_ref(range: Option<&str>, staged: bool, repo_root: &Path) -> Option<String> {
    if staged {
        return Some("HEAD".to_string());
    }
    match range {
        Some(r) => {
            if let Some((left, right)) = r.split_once("...") {
                let left = if left.is_empty() { "HEAD" } else { left };
                let right = if right.is_empty() { "HEAD" } else { right };
                if let Ok(out) = Command::new("git")
                    .current_dir(repo_root)
                    .args(["merge-base", left, right])
                    .output()
                {
                    if out.status.success() {
                        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if !sha.is_empty() {
                            return Some(sha);
                        }
                    }
                }
                return Some(left.to_string());
            }
            if let Some((left, _right)) = r.split_once("..") {
                let left = if left.is_empty() { "HEAD" } else { left };
                return Some(left.to_string());
            }
            Some(r.to_string())
        }
        None => Some("HEAD".to_string()),
    }
}

/// Fetch file content at a specific git revision using `git show <base_ref>:<rel_path>`.
pub fn git_show_file(repo_root: &Path, base_ref: &str, rel_path: &str) -> Option<String> {
    let spec = format!("{}:{}", base_ref, rel_path);
    let out = Command::new("git")
        .current_dir(repo_root)
        .args(["show", &spec])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}
