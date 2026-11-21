use crate::ast::{Finding, Severity};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityOverride {
    Blocker,
    Warning,
    Off,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub disable: Vec<String>,
    pub ignore: Vec<String>,
    pub strict: Option<bool>,
    pub severity: BTreeMap<String, SeverityOverride>,
}

pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# yupp configuration (.yupp.toml)
# Docs: https://github.com/yupp-cli/yupp

# Fail with exit code 1 on warnings as well as blockers
strict = false

# Rule IDs to disable completely
disable = [
  # "slop/rust-unwrap",
  # "slop/debug-leftover",
  # "test-theater/untested-new-public",
]

# File paths, directory prefixes, or glob suffixes to skip
ignore = [
  "migrations/",
  "generated/",
  "*.min.js",
  "*.generated.ts",
]

# Override severity per rule: "blocker", "warning", or "off"
[severity]
# "slop/debug-leftover" = "blocker"
# "slop/silent-fallback-catch" = "blocker"
# "slop/rust-unwrap" = "off"
"#;

impl Config {
    pub fn load(repo_root: &Path, explicit_path: Option<&Path>) -> Result<Self, String> {
        let path: PathBuf = match explicit_path {
            Some(p) => {
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    repo_root.join(p)
                }
            }
            None => {
                let candidate = repo_root.join(".yupp.toml");
                if !candidate.exists() {
                    return Ok(Self::default());
                }
                candidate
            }
        };

        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
        Self::parse_toml(&raw)
    }

    /// Minimal, zero-dependency TOML parser for `.yupp.toml`.
    /// Supports `#` comments, `[section]` headers, booleans, quoted strings,
    /// and single- or multi-line string arrays.
    pub fn parse_toml(input: &str) -> Result<Self, String> {
        let mut cfg = Config::default();
        let mut section = String::new();
        let mut in_array_key: Option<String> = None;
        let mut array_buf = String::new();

        for (idx, raw_line) in input.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_toml_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(ref key) = in_array_key.clone() {
                array_buf.push(' ');
                array_buf.push_str(line);
                if line.contains(']') {
                    let items = parse_string_array(&array_buf, line_no)?;
                    assign_array(&mut cfg, &section, key, items, line_no)?;
                    in_array_key = None;
                    array_buf.clear();
                }
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_string();
                continue;
            }

            let Some((raw_k, raw_v)) = line.split_once('=') else {
                return Err(format!("invalid .yupp.toml syntax on line {}", line_no));
            };
            let key = unquote(raw_k.trim());
            let val = raw_v.trim();

            if val.starts_with('[') {
                if val.contains(']') {
                    let items = parse_string_array(val, line_no)?;
                    assign_array(&mut cfg, &section, &key, items, line_no)?;
                } else {
                    in_array_key = Some(key);
                    array_buf = val.to_string();
                }
                continue;
            }

            if section.is_empty() {
                if key == "strict" {
                    match val {
                        "true" => cfg.strict = Some(true),
                        "false" => cfg.strict = Some(false),
                        _ => {
                            return Err(format!(
                                "invalid boolean for `strict` on line {}: {}",
                                line_no, val
                            ))
                        }
                    }
                }
            } else if section == "severity" {
                let sev_str = unquote(val).to_lowercase();
                let sev = match sev_str.as_str() {
                    "blocker" | "error" => SeverityOverride::Blocker,
                    "warning" | "warn" => SeverityOverride::Warning,
                    "off" | "none" | "disable" => SeverityOverride::Off,
                    _ => {
                        return Err(format!(
                            "invalid severity `{}` for rule `{}` on line {}",
                            sev_str, key, line_no
                        ))
                    }
                };
                cfg.severity.insert(key, sev);
            }
        }

        if let Some(k) = in_array_key {
            return Err(format!("unclosed array for `{}` in .yupp.toml", k));
        }

        Ok(cfg)
    }

    pub fn is_ignored(&self, rel_path: &str) -> bool {
        let normalized = rel_path.replace('\\', "/");
        for pat in &self.ignore {
            let p = pat.trim().replace('\\', "/");
            if p.is_empty() {
                continue;
            }
            if let Some(suffix) = p.strip_prefix('*') {
                if normalized.ends_with(suffix) {
                    return true;
                }
            } else if p.ends_with('/') {
                if normalized.starts_with(&p) || normalized.contains(&format!("/{}", p)) {
                    return true;
                }
            } else if normalized == p
                || normalized.starts_with(&format!("{}/", p))
                || normalized.ends_with(&format!("/{}", p))
            {
                return true;
            }
        }
        false
    }

    pub fn apply_to_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter_map(|mut f| {
                if self.disable.iter().any(|r| r == &f.rule || rule_matches_prefix(r, &f.rule)) {
                    return None;
                }
                if let Some(override_sev) = self.severity.get(&f.rule) {
                    match override_sev {
                        SeverityOverride::Off => return None,
                        SeverityOverride::Blocker => f.severity = Severity::Blocker,
                        SeverityOverride::Warning => f.severity = Severity::Warning,
                    }
                }
                Some(f)
            })
            .collect()
    }
}

fn rule_matches_prefix(pattern: &str, rule: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        rule.starts_with(&format!("{}/", prefix))
    } else {
        false
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_double && !in_single => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() >= 2 {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn parse_string_array(raw: &str, line_no: usize) -> Result<Vec<String>, String> {
    let start = raw
        .find('[')
        .ok_or_else(|| format!("expected `[` on line {}", line_no))?;
    let end = raw
        .rfind(']')
        .ok_or_else(|| format!("expected `]` on line {}", line_no))?;
    if end < start {
        return Err(format!("malformed array on line {}", line_no));
    }
    let inner = &raw[start + 1..end];
    let mut items = Vec::new();
    for part in inner.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        items.push(unquote(trimmed));
    }
    Ok(items)
}

fn assign_array(
    cfg: &mut Config,
    section: &str,
    key: &str,
    items: Vec<String>,
    line_no: usize,
) -> Result<(), String> {
    if !section.is_empty() {
        return Err(format!(
            "unexpected array `{}` inside [{}] on line {}",
            key, section, line_no
        ));
    }
    match key {
        "disable" => cfg.disable = items,
        "ignore" => cfg.ignore = items,
        _ => {}
    }
    Ok(())
}

pub fn init_config(repo_root: &Path, force: bool, hook: Option<&str>) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    let cfg_path = repo_root.join(".yupp.toml");

    if cfg_path.exists() && !force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            cfg_path.display()
        ));
    }
    fs::write(&cfg_path, DEFAULT_CONFIG_TEMPLATE)
        .map_err(|e| format!("failed to write {}: {}", cfg_path.display(), e))?;
    actions.push(format!("Created {}", cfg_path.display()));

    if let Some(hook_name) = hook {
        let valid = matches!(hook_name, "pre-commit" | "pre-push");
        if !valid {
            return Err(format!(
                "unsupported git hook `{}` (supported: pre-commit, pre-push)",
                hook_name
            ));
        }
        let git_hooks_dir = repo_root.join(".git").join("hooks");
        if !git_hooks_dir.exists() {
            return Err(format!(
                "git hooks directory not found at {} (is this a git repository?)",
                git_hooks_dir.display()
            ));
        }
        let hook_path = git_hooks_dir.join(hook_name);
        if hook_path.exists() && !force {
            return Err(format!(
                "git hook {} already exists (pass --force to overwrite)",
                hook_path.display()
            ));
        }
        let script = match hook_name {
            "pre-commit" => "#!/usr/bin/env sh\n# Installed by yupp init\nexec yupp --staged\n",
            "pre-push" => "#!/usr/bin/env sh\n# Installed by yupp init\nbase=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || echo main)\nexec yupp \"${base}..HEAD\"\n",
            _ => unreachable!(),
        };
        fs::write(&hook_path, script)
            .map_err(|e| format!("failed to write hook {}: {}", hook_path.display(), e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path)
                .map_err(|e| format!("failed to read hook permissions: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .map_err(|e| format!("failed to chmod +x hook: {}", e))?;
        }

        actions.push(format!("Installed executable git hook {}", hook_path.display()));
    }

    Ok(actions)
}
