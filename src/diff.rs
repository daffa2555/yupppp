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
    #[serde(default)]
    pub is_deleted: bool,
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

fn parse_hunk_count(spec: &str) -> usize {
    match spec.split_once(',') {
        Some((_, cnt)) => cnt.parse().unwrap_or(1),
        None => 1,
    }
}

pub fn parse_unified_diff(raw: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    let mut pending_old_path: Option<String> = None;
    let mut in_hunk = false;
    let mut old_line: usize = 0;
    let mut new_line: usize = 0;
    let mut old_rem: usize = 0;
    let mut new_rem: usize = 0;

    let lines: Vec<&str> = raw.lines().collect();
    for (idx, &line) in lines.iter().enumerate() {
        let next_line = lines.get(idx + 1).copied();

        if line.starts_with("diff --git ") {
            if let Some(prev) = current.take() {
                files.push(prev);
            }
            pending_old_path = None;
            in_hunk = false;
            old_line = 0;
            new_line = 0;
            old_rem = 0;
            new_rem = 0;
            continue;
        }

        if line.starts_with("@@ ") {
            // Parse @@ -old_start[,count] +new_start[,count] @@
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let old_spec = parts[1].trim_start_matches('-');
                let new_spec = parts[2].trim_start_matches('+');
                old_line = old_spec
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                new_line = new_spec
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                old_rem = parse_hunk_count(old_spec);
                new_rem = parse_hunk_count(new_spec);
            }
            in_hunk = true;
            continue;
        }

        let is_minus_header = !in_hunk
            || (old_rem == 0
                && new_rem == 0)
            || (new_rem == 0
                && next_line.is_some_and(|n| n.starts_with("+++ b/") || n.starts_with("+++ /dev/null")));
        if is_minus_header {
            if let Some(rest) = line.strip_prefix("--- a/") {
                let clean = rest.split('\t').next().unwrap_or(rest).trim();
                pending_old_path = Some(clean.to_string());
                in_hunk = false;
                old_rem = 0;
                new_rem = 0;
                continue;
            }
            if line.starts_with("--- /dev/null") {
                pending_old_path = None;
                in_hunk = false;
                old_rem = 0;
                new_rem = 0;
                continue;
            }
        }

        let is_plus_header = !in_hunk
            || next_line.is_some_and(|n| n.starts_with("@@ "))
            || (new_rem == 0
                && (old_rem == 0
                    || next_line.is_none()
                    || next_line.is_some_and(|n| n.starts_with("diff --git "))));
        if is_plus_header {
            if let Some(rest) = line.strip_prefix("+++ b/") {
                pending_old_path = None;
                if let Some(prev) = current.take() {
                    files.push(prev);
                }
                let clean = rest.split('\t').next().unwrap_or(rest).trim();
                current = Some(FileDiff {
                    path: clean.to_string(),
                    added: Vec::new(),
                    removed: Vec::new(),
                    is_deleted: false,
                });
                in_hunk = false;
                old_line = 0;
                new_line = 0;
                old_rem = 0;
                new_rem = 0;
                continue;
            }
            if line.starts_with("+++ /dev/null") {
                if let Some(prev) = current.take() {
                    files.push(prev);
                }
                if let Some(old_path) = pending_old_path.take() {
                    current = Some(FileDiff {
                        path: old_path,
                        added: Vec::new(),
                        removed: Vec::new(),
                        is_deleted: true,
                    });
                }
                in_hunk = false;
                old_line = 0;
                new_line = 0;
                old_rem = 0;
                new_rem = 0;
                continue;
            }
        }

        if !in_hunk {
            continue;
        }

        let Some(file) = current.as_mut() else {
            continue;
        };

        if let Some(added) = line.strip_prefix('+') {
            file.added.push(DiffLine {
                line_no: new_line,
                content: added.to_string(),
            });
            new_line += 1;
            new_rem = new_rem.saturating_sub(1);
        } else if let Some(removed) = line.strip_prefix('-') {
            file.removed.push(DiffLine {
                line_no: old_line,
                content: removed.to_string(),
            });
            old_line += 1;
            old_rem = old_rem.saturating_sub(1);
        } else if line.starts_with(' ') {
            old_line += 1;
            new_line += 1;
            old_rem = old_rem.saturating_sub(1);
            new_rem = new_rem.saturating_sub(1);
        }

        if old_rem == 0 && new_rem == 0 {
            in_hunk = false;
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

/// Resolve the git target/head ref used to fetch post-change file contents
/// (`git show <head>:<file>`). Returns `Some("")` for `--staged` (git index `:<file>`),
/// `Some(<right>)` for range diffs like `A..B` or `A...B`, and `None` when the
/// working tree on disk is the target.
pub fn resolve_head_ref(range: Option<&str>, staged: bool) -> Option<String> {
    if staged {
        return Some(String::new());
    }
    let r = range?;
    if let Some((_left, right)) = r.split_once("...") {
        let right = if right.is_empty() { "HEAD" } else { right };
        return Some(right.to_string());
    }
    if let Some((_left, right)) = r.split_once("..") {
        let right = if right.is_empty() { "HEAD" } else { right };
        return Some(right.to_string());
    }
    None
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
