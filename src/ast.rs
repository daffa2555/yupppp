use crate::config::Config;
use crate::diff::{git_show_file, FileDiff};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use tree_sitter::{Language, Node, Parser};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Blocker,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    BreakingChange,
    TestTheater,
    SilentSlop,
    SecretLeak,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlastEntry {
    pub file: String,
    pub symbol: String,
    pub callers: Vec<CallerRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_change: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unupdated_callers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallerRef {
    pub file: String,
    pub is_test: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    pub base_ref: Option<String>,
    pub head_ref: Option<String>,
    pub config: Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lang {
    Python,
    Rust,
    JavaScript,
    TypeScript,
    Go,
}

#[derive(Debug, Clone)]
struct ParamInfo {
    text: String,
    has_default: bool,
}

#[derive(Debug, Clone)]
struct FnSignature {
    name: String,
    params: Vec<ParamInfo>,
    return_type: Option<String>,
    is_public: bool,
    line: usize,
}

#[derive(Debug, Clone)]
struct BreakingEvent {
    file: String,
    symbol: String,
    line: usize,
    removed: bool,
    detail: String,
}

#[derive(Debug, Clone)]
struct BodyFingerprint {
    lang: Lang,
    hash: u64,
    file: String,
    line: usize,
    name: String,
}

#[derive(Debug, Clone, Default)]
struct DiffContext {
    modified_symbols: BTreeSet<String>,
    modified_modules: BTreeSet<String>,
}

fn detect_lang(path: &str) -> Option<Lang> {
    let p = path.to_lowercase();
    if p.ends_with(".py") {
        Some(Lang::Python)
    } else if p.ends_with(".rs") {
        Some(Lang::Rust)
    } else if p.ends_with(".ts") || p.ends_with(".tsx") {
        Some(Lang::TypeScript)
    } else if p.ends_with(".js")
        || p.ends_with(".jsx")
        || p.ends_with(".mjs")
        || p.ends_with(".cjs")
    {
        Some(Lang::JavaScript)
    } else if p.ends_with(".go") {
        Some(Lang::Go)
    } else {
        None
    }
}

fn ts_language(lang: Lang) -> Language {
    match lang {
        Lang::Python => tree_sitter_python::LANGUAGE.into(),
        Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
        Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Lang::Go => tree_sitter_go::LANGUAGE.into(),
    }
}

fn is_test_path(rel_path: &str) -> bool {
    FileDiff {
        path: rel_path.to_string(),
        added: vec![],
        removed: vec![],
        is_deleted: false,
    }
    .is_test_file()
}

const ASSERT_PATTERN: &str = r"(\bassert\b|\bassert_eq!\s*\(|\bassert_ne!\s*\(|\bassert!\s*\(|\bexpect\s*\(|\btoBe\s*\(|\btoEqual\s*\(|\bassertEqual\b|\bassertTrue\b|\bassertFalse\b|\bassertRaises\b|\bt\.Error|\bt\.Fatal|\brequire\.|\bassert\.)";

fn count_assertions(lines: &[crate::diff::DiffLine]) -> usize {
    let assert_re = Regex::new(ASSERT_PATTERN).unwrap();
    lines
        .iter()
        .filter(|l| {
            let trimmed = l.content.trim();
            !trimmed.starts_with("//") && !trimmed.starts_with('#') && assert_re.is_match(trimmed)
        })
        .count()
}

pub fn analyze_diff(files: &[FileDiff], repo_root: &Path) -> (Vec<Finding>, Vec<BlastEntry>) {
    analyze_diff_with_options(files, repo_root, &AnalyzeOptions::default())
}

pub fn analyze_diff_with_options(
    files: &[FileDiff],
    repo_root: &Path,
    opts: &AnalyzeOptions,
) -> (Vec<Finding>, Vec<BlastEntry>) {
    let mut findings = Vec::new();
    let mut changed_symbols: Vec<(String, String)> = Vec::new();
    let mut breaking_events: Vec<BreakingEvent> = Vec::new();
    let mut new_public_symbols: Vec<(String, String, usize)> = Vec::new();
    let mut body_fingerprints: Vec<BodyFingerprint> = Vec::new();
    let mut diff_ctx = DiffContext::default();

    let modified_files: BTreeSet<String> = files
        .iter()
        .filter(|f| !opts.config.is_ignored(&f.path))
        .map(|f| f.path.replace('\\', "/"))
        .collect();

    let skip_re = Regex::new(
        r"(\.skip\s*\(|\bxit\s*\(|\bxdescribe\s*\(|@pytest\.mark\.skip|@unittest\.skip|#\[ignore\b|t\.Skip\s*\()",
    )
    .unwrap();
    let trivial_assert_re = Regex::new(
        r"(\bassert\s+True\b|\bassert\s+1\s*==\s*1\b|\bassert\s+not\s+False\b|\bexpect\s*\(\s*true\s*\)\s*\.toBe\s*\(\s*true\s*\)|\bexpect\s*\(\s*true\s*\)\s*\.toBeTruthy\s*\(\s*\)|\bexpect\s*\(\s*1\s*\)\s*\.toBe\s*\(\s*1\s*\)|\bassert!\s*\(\s*true\s*\)|\bassert_eq!\s*\(\s*1\s*,\s*1\s*\))",
    )
    .unwrap();
    let secret_rules: Vec<(&str, Regex)> = vec![
        (
            "secret/stripe",
            Regex::new(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b").unwrap(),
        ),
        (
            "secret/aws",
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        ),
        (
            "secret/github",
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap(),
        ),
        (
            "secret/db-uri",
            Regex::new(r"(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^/\s@]+@")
                .unwrap(),
        ),
        (
            "secret/jwt",
            Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
        ),
    ];
    let suppress_re =
        Regex::new(r"(@ts-ignore|@ts-nocheck|#\s*type:\s*ignore|#\[allow\(warnings\)\])").unwrap();
    let unwrap_re = Regex::new(r"\.(unwrap|expect)\s*\(").unwrap();
    let todo_re =
        Regex::new(r"(\btodo!\s*\(|\bunimplemented!\s*\(|\bNotImplementedError\b)").unwrap();
    let placeholder_comment_re = Regex::new(
        r"(?i)(?://|#|/\*)\s*(?:TODO\s*:?\s*(?:implement|fill|add|complete|fix|stub)|implement\s+(?:logic|this|here|me|later)|placeholder\s+implementation)",
    )
    .unwrap();
    let hard_debug_re =
        Regex::new(r"(\bbreakpoint\s*\(|\bpdb\.set_trace\s*\(|\bipdb\.set_trace\s*\(|\bdebugger\s*;)").unwrap();
    let soft_debug_re =
        Regex::new(r"(\bconsole\.(log|debug)\s*\(|\bdbg!\s*\(|\bfmt\.Println\s*\()").unwrap();

    // Process non-test files first so diff_ctx has all modified production symbols & modules
    // before analyzing test files for diff-aware mock-testing-mock detection.
    let ordered_files: Vec<&FileDiff> = files
        .iter()
        .filter(|f| !opts.config.is_ignored(&f.path) && !f.is_test_file())
        .chain(
            files
                .iter()
                .filter(|f| !opts.config.is_ignored(&f.path) && f.is_test_file()),
        )
        .collect();

    for f in ordered_files {
        let is_test = f.is_test_file();
        let lang = detect_lang(&f.path);

        if !is_test && lang.is_some() {
            if let Some(stem) = Path::new(&f.path).file_stem().and_then(|s| s.to_str()) {
                if stem.len() >= 2 && stem != "mod" && stem != "index" && stem != "__init__" {
                    diff_ctx.modified_modules.insert(stem.to_string());
                }
            }
        }

        // 1. Test Theater: assertion removal / weakening in test files
        if is_test {
            let removed_asserts = count_assertions(&f.removed);
            let added_asserts = count_assertions(&f.added);
            if removed_asserts > 0 && added_asserts < removed_asserts {
                let first_line = f.removed.first().map(|l| l.line_no).unwrap_or(1);
                findings.push(Finding {
                    severity: Severity::Blocker,
                    category: Category::TestTheater,
                    file: f.path.clone(),
                    line: first_line,
                    rule: "test-theater/assertions-removed".into(),
                    message: format!(
                        "Test assertions reduced (-{} removed, +{} added)",
                        removed_asserts, added_asserts
                    ),
                });
            }
        }

        // Pre-read post-change file content (from `head_ref` / git index when scanning
        // a commit range or `--staged`, otherwise from the working tree on disk) so we
        // can build a Tree-sitter string masker for multiline string literals before
        // running line-based slop checks.
        let disk_source = if !f.is_deleted {
            opts.head_ref
                .as_deref()
                .and_then(|head| git_show_file(repo_root, head, &f.path))
                .or_else(|| fs::read_to_string(repo_root.join(&f.path)).ok())
        } else {
            None
        };
        let string_masker = match (lang, disk_source.as_deref()) {
            (Some(l), Some(src)) => StringMasker::new(l, src),
            _ => None,
        };

        // 2. Per-added-line deterministic checks
        for dl in &f.added {
            let text = dl.content.trim();
            if text.is_empty() {
                continue;
            }
            let is_comment =
                text.starts_with("//") || text.starts_with('#') || text.starts_with('*');
            // Mask string literals (including multiline strings via Tree-sitter node ranges)
            // so rule descriptions, docstrings, raw strings, and template literals containing
            // `"todo!()"` or `"console.log(1)"` do not trigger false positives.
            let line_is_test = is_test
                || string_masker
                    .as_ref()
                    .is_some_and(|m| m.is_rust_test_line(dl.line_no));
            let code_with_comments = string_masker
                .as_ref()
                .and_then(|m| m.mask_line(dl.line_no, &dl.content))
                .unwrap_or_else(|| strip_string_literals(text));
            let code_only = string_masker
                .as_ref()
                .and_then(|m| m.mask_code_only(dl.line_no, &dl.content))
                .unwrap_or_else(|| strip_inline_comment(lang, &code_with_comments));

            if line_is_test && skip_re.is_match(&code_only) {
                findings.push(Finding {
                    severity: Severity::Blocker,
                    category: Category::TestTheater,
                    file: f.path.clone(),
                    line: dl.line_no,
                    rule: "test-theater/skipped-test".into(),
                    message: "Test skipped/ignored in diff".into(),
                });
            }

            if line_is_test && trivial_assert_re.is_match(&code_only) {
                findings.push(Finding {
                    severity: Severity::Blocker,
                    category: Category::TestTheater,
                    file: f.path.clone(),
                    line: dl.line_no,
                    rule: "test-theater/trivial-assertion".into(),
                    message: "Trivial tautology assertion (always passes)".into(),
                });
            }

            // Secrets live inside string literals, so match against raw `text`.
            for (rule_name, re) in &secret_rules {
                if re.is_match(text) {
                    findings.push(Finding {
                        severity: Severity::Blocker,
                        category: Category::SecretLeak,
                        file: f.path.clone(),
                        line: dl.line_no,
                        rule: (*rule_name).into(),
                        message: "Hardcoded secret/credential pattern introduced".into(),
                    });
                }
            }

            if lang.is_some() && !is_comment && hard_debug_re.is_match(&code_only) {
                findings.push(Finding {
                    severity: Severity::Warning,
                    category: Category::SilentSlop,
                    file: f.path.clone(),
                    line: dl.line_no,
                    rule: "slop/debug-leftover".into(),
                    message: "Interactive debugger breakpoint leftover".into(),
                });
            }

            if lang.is_some() && !line_is_test {
                if !is_comment && soft_debug_re.is_match(&code_only) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        category: Category::SilentSlop,
                        file: f.path.clone(),
                        line: dl.line_no,
                        rule: "slop/debug-leftover".into(),
                        message: "Debug print leftover (console.log / dbg! / fmt.Println)".into(),
                    });
                }
                if suppress_re.is_match(&code_with_comments) {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        category: Category::SilentSlop,
                        file: f.path.clone(),
                        line: dl.line_no,
                        rule: "slop/type-suppression".into(),
                        message: "Compiler/type-checker suppression added".into(),
                    });
                }
                if lang == Some(Lang::Rust) && unwrap_re.is_match(&code_only) && !is_comment {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        category: Category::SilentSlop,
                        file: f.path.clone(),
                        line: dl.line_no,
                        rule: "slop/rust-unwrap".into(),
                        message: "New .unwrap()/.expect() panic hazard introduced".into(),
                    });
                }
                if (todo_re.is_match(&code_only) && !is_comment)
                    || placeholder_comment_re.is_match(&code_with_comments)
                {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        category: Category::SilentSlop,
                        file: f.path.clone(),
                        line: dl.line_no,
                        rule: "slop/unfinished-stub".into(),
                        message: "Unfinished stub or placeholder implementation".into(),
                    });
                }
            }
        }

        // 3. Tree-sitter AST checks on the actual file on disk (or deleted file's old AST)
        let Some(lang) = lang else { continue };

        if f.is_deleted {
            if !is_test {
                let old_src = opts
                    .base_ref
                    .as_deref()
                    .and_then(|base| git_show_file(repo_root, base, &f.path))
                    .or_else(|| {
                        if f.removed.is_empty() {
                            None
                        } else {
                            Some(
                                f.removed
                                    .iter()
                                    .map(|l| l.content.as_str())
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                            )
                        }
                    });
                if let Some(src) = old_src {
                    let old_sigs = extract_signatures(lang, &src);
                    for old_sig in old_sigs.values() {
                        if !old_sig.is_public || is_generic_symbol_name(&old_sig.name) {
                            continue;
                        }
                        changed_symbols.push((f.path.clone(), old_sig.name.clone()));
                        diff_ctx.modified_symbols.insert(old_sig.name.clone());
                        breaking_events.push(BreakingEvent {
                            file: f.path.clone(),
                            symbol: old_sig.name.clone(),
                            line: old_sig.line.max(1),
                            removed: true,
                            detail: format!(
                                "Public symbol `{}` was removed (file deleted)",
                                old_sig.name
                            ),
                        });
                    }
                }
            }
            continue;
        }

        let Some(source) = disk_source else {
            continue;
        };
        let added_lines: BTreeSet<usize> = f.added.iter().map(|l| l.line_no).collect();

        // 3a. Old-AST vs New-AST signature diff (when base_ref is available)
        let old_sigs = opts
            .base_ref
            .as_deref()
            .and_then(|base| git_show_file(repo_root, base, &f.path))
            .map(|old_src| extract_signatures(lang, &old_src));

        let new_sigs = extract_signatures(lang, &source);

        if !is_test {
            if let Some(ref old_map) = old_sigs {
                for (sig_key, old_sig) in old_map {
                    if !old_sig.is_public || is_generic_symbol_name(&old_sig.name) {
                        continue;
                    }
                    match new_sigs.get(sig_key) {
                        None => {
                            changed_symbols.push((f.path.clone(), old_sig.name.clone()));
                            diff_ctx.modified_symbols.insert(old_sig.name.clone());
                            breaking_events.push(BreakingEvent {
                                file: f.path.clone(),
                                symbol: old_sig.name.clone(),
                                line: 1,
                                removed: true,
                                detail: format!("Public symbol `{}` was removed", old_sig.name),
                            });
                        }
                        Some(new_sig) => {
                            if let Some(diff_desc) = detect_breaking_signature(old_sig, new_sig) {
                                changed_symbols.push((f.path.clone(), new_sig.name.clone()));
                                diff_ctx.modified_symbols.insert(new_sig.name.clone());
                                breaking_events.push(BreakingEvent {
                                    file: f.path.clone(),
                                    symbol: new_sig.name.clone(),
                                    line: new_sig.line,
                                    removed: false,
                                    detail: diff_desc,
                                });
                            }
                        }
                    }
                }
            }

            // Collect newly added public/exported functions for untested-new-public check
            for (sig_key, sig) in &new_sigs {
                if !sig.is_public || is_generic_symbol_name(&sig.name) {
                    continue;
                }
                let is_newly_added = match old_sigs {
                    Some(ref old_map) => {
                        !old_map.contains_key(sig_key) && added_lines.contains(&sig.line)
                    }
                    None => added_lines.contains(&sig.line),
                };
                if is_newly_added {
                    new_public_symbols.push((f.path.clone(), sig.name.clone(), sig.line));
                }
            }
        }

        analyze_ast(
            &f.path,
            lang,
            &source,
            is_test,
            &added_lines,
            &mut findings,
            &mut changed_symbols,
            &mut body_fingerprints,
            &mut diff_ctx,
        );
    }

    // 4. Duplicate function/block detection via AST structural hashing across the PR
    detect_duplicate_bodies(&body_fingerprints, &mut findings);

    // 5. Single repo walk for Blast Radius + Breaking Unupdated Callers + Untested New Public Functions
    let (mut blast, test_refs) = scan_repo_references(
        repo_root,
        &changed_symbols,
        &new_public_symbols,
        &opts.config,
    );

    // Enrich blast radius and emit conservative (Warning) breaking change findings
    let mut breaking_by_key: BTreeMap<(String, String), &BreakingEvent> = BTreeMap::new();
    for ev in &breaking_events {
        breaking_by_key.insert((ev.file.clone(), ev.symbol.clone()), ev);
    }

    for entry in &mut blast {
        if let Some(ev) = breaking_by_key.get(&(entry.file.clone(), entry.symbol.clone())) {
            entry.signature_change = Some(ev.detail.clone());
            entry.unupdated_callers = entry
                .callers
                .iter()
                .filter(|c| !modified_files.contains(&c.file))
                .map(|c| c.file.clone())
                .collect();
        }
    }

    // Keep breaking signature / symbol-removal findings conservative (Warning) to avoid
    // noisy false-positive blockers; users can promote to Blocker via `.yupp.toml` or `--strict`.
    for ev in &breaking_events {
        let unupdated: Vec<String> = blast
            .iter()
            .find(|b| b.file == ev.file && b.symbol == ev.symbol)
            .map(|b| b.unupdated_callers.clone())
            .unwrap_or_default();

        if ev.removed {
            let msg = if unupdated.is_empty() {
                ev.detail.clone()
            } else {
                format!(
                    "{} — potential unupdated caller(s): {}",
                    ev.detail,
                    unupdated.join(", ")
                )
            };
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::BreakingChange,
                file: ev.file.clone(),
                line: ev.line,
                rule: "breaking/public-symbol-removed".into(),
                message: msg,
            });
        } else {
            let msg = if unupdated.is_empty() {
                format!("Public signature of `{}` changed: {}", ev.symbol, ev.detail)
            } else {
                format!(
                    "Public signature of `{}` changed ({}) — potential unupdated caller(s): {}",
                    ev.symbol,
                    ev.detail,
                    unupdated.join(", ")
                )
            };
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::BreakingChange,
                file: ev.file.clone(),
                line: ev.line,
                rule: "breaking/signature-changed".into(),
                message: msg,
            });
        }
    }

    // Emit untested-new-public findings
    for (file, sym, line) in &new_public_symbols {
        if !test_refs.contains(sym) {
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::TestTheater,
                file: file.clone(),
                line: *line,
                rule: "test-theater/untested-new-public".into(),
                message: format!(
                    "Newly added public function `{}` has 0 references in test files",
                    sym
                ),
            });
        }
    }

    let findings = opts.config.apply_to_findings(findings);
    (findings, blast)
}

/// Filter out short or generic/ambiguous method names (`init`, `save`, `run`, `get`, `set`,
/// `close`, `parse`, `handle`, etc.) that cause noisy cross-file false positives across
/// unrelated classes/structs.
fn is_generic_symbol_name(name: &str) -> bool {
    if name.len() < 3 {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "main"
            | "new"
            | "init"
            | "__init__"
            | "default"
            | "clone"
            | "drop"
            | "fmt"
            | "from"
            | "into"
            | "try_from"
            | "try_into"
            | "as_ref"
            | "as_mut"
            | "deref"
            | "get"
            | "set"
            | "put"
            | "post"
            | "patch"
            | "delete"
            | "remove"
            | "add"
            | "push"
            | "pop"
            | "insert"
            | "update"
            | "create"
            | "save"
            | "load"
            | "read"
            | "write"
            | "open"
            | "close"
            | "start"
            | "stop"
            | "run"
            | "exec"
            | "execute"
            | "call"
            | "apply"
            | "handle"
            | "process"
            | "parse"
            | "format"
            | "render"
            | "build"
            | "check"
            | "validate"
            | "reset"
            | "clear"
            | "flush"
            | "send"
            | "recv"
            | "next"
            | "len"
            | "is_empty"
            | "count"
            | "find"
            | "search"
            | "filter"
            | "map"
            | "reduce"
            | "sort"
            | "to_string"
            | "tostring"
            | "valueof"
            | "equals"
            | "hashcode"
            | "string"
            | "error"
            | "setup"
            | "teardown"
            | "configure"
            | "connect"
            | "disconnect"
    )
}

/// Tracks Tree-sitter string literal ranges, comment ranges, and Rust inline
/// `#[cfg(test)]` / `#[test]` line spans so multiline strings, trailing inline
/// comments, and Rust inline unit test modules are handled with AST precision.
struct StringMasker<'a> {
    source: &'a str,
    line_spans: Vec<(usize, usize)>,
    string_ranges: Vec<(usize, usize)>,
    string_and_comment_ranges: Vec<(usize, usize)>,
    rust_test_lines: Vec<(usize, usize)>,
}

impl<'a> StringMasker<'a> {
    fn new(lang: Lang, source: &'a str) -> Option<Self> {
        let mut parser = Parser::new();
        parser.set_language(&ts_language(lang)).ok()?;
        let tree = parser.parse(source, None)?;

        let mut line_spans = Vec::new();
        let mut offset = 0usize;
        for raw_line in source.split('\n') {
            let line_len = raw_line
                .strip_suffix('\r')
                .map_or(raw_line.len(), |s| s.len());
            line_spans.push((offset, offset + line_len));
            offset += raw_line.len() + 1;
        }

        let mut string_ranges = Vec::new();
        collect_string_ranges(lang, tree.root_node(), &mut string_ranges);
        string_ranges.sort_unstable();

        let mut comment_ranges = Vec::new();
        collect_comment_ranges(tree.root_node(), &mut comment_ranges);

        let mut string_and_comment_ranges = string_ranges.clone();
        string_and_comment_ranges.extend(comment_ranges);
        string_and_comment_ranges.sort_unstable();

        let mut rust_test_lines = Vec::new();
        if lang == Lang::Rust {
            collect_rust_test_line_ranges(tree.root_node(), source.as_bytes(), &mut rust_test_lines);
        }

        Some(Self {
            source,
            line_spans,
            string_ranges,
            string_and_comment_ranges,
            rust_test_lines,
        })
    }

    fn is_rust_test_line(&self, line_no: usize) -> bool {
        self.rust_test_lines
            .iter()
            .any(|&(start, end)| line_no >= start && line_no <= end)
    }

    fn mask_ranges(&self, line_no: usize, diff_line_content: &str, ranges: &[(usize, usize)]) -> Option<String> {
        if line_no == 0 || line_no > self.line_spans.len() {
            return None;
        }
        let (lstart, lend) = self.line_spans[line_no - 1];
        let disk_line = &self.source[lstart..lend];
        if disk_line != diff_line_content.trim_end_matches('\r') {
            return None;
        }

        let idx = ranges.partition_point(|&(_, rend)| rend <= lstart);
        if idx >= ranges.len() || ranges[idx].0 >= lend {
            return Some(disk_line.trim().to_string());
        }

        let mut out = String::with_capacity(lend - lstart);
        let mut cursor = lstart;
        for &(rstart, rend) in &ranges[idx..] {
            if rstart >= lend {
                break;
            }
            let seg_start = rstart.max(lstart);
            if seg_start > cursor {
                out.push_str(&self.source[cursor..seg_start]);
            }
            out.push(' ');
            cursor = cursor.max(rend.min(lend));
            if cursor >= lend {
                break;
            }
        }
        if cursor < lend {
            out.push_str(&self.source[cursor..lend]);
        }
        Some(out.trim().to_string())
    }

    fn mask_line(&self, line_no: usize, diff_line_content: &str) -> Option<String> {
        self.mask_ranges(line_no, diff_line_content, &self.string_ranges)
    }

    fn mask_code_only(&self, line_no: usize, diff_line_content: &str) -> Option<String> {
        self.mask_ranges(line_no, diff_line_content, &self.string_and_comment_ranges)
    }
}

fn collect_comment_ranges(node: Node, out: &mut Vec<(usize, usize)>) {
    if matches!(node.kind(), "comment" | "line_comment" | "block_comment") {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_comment_ranges(child, out);
    }
}

fn has_rust_cfg_test_attr(node: Node, bytes: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "attribute_item" {
            let txt = sib.utf8_text(bytes).unwrap_or("");
            let compact: String = txt.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("cfg(test)") || compact.contains("cfg(all(test,") || compact.contains(",test))") {
                return true;
            }
            prev = sib.prev_sibling();
        } else {
            break;
        }
    }
    false
}

fn is_inside_rust_cfg_test(node: Node, bytes: &[u8]) -> bool {
    let mut cur = Some(node);
    while let Some(n) = cur {
        if n.kind() == "mod_item" && has_rust_cfg_test_attr(n, bytes) {
            return true;
        }
        if n.kind() == "function_item" && has_rust_test_attr(n, bytes) {
            return true;
        }
        cur = n.parent();
    }
    false
}

fn collect_rust_test_line_ranges(node: Node, bytes: &[u8], out: &mut Vec<(usize, usize)>) {
    if (node.kind() == "mod_item" && has_rust_cfg_test_attr(node, bytes))
        || (node.kind() == "function_item" && has_rust_test_attr(node, bytes))
    {
        out.push((node.start_position().row + 1, node.end_position().row + 1));
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_test_line_ranges(child, bytes, out);
    }
}

fn strip_inline_comment(lang: Option<Lang>, code_with_strings_stripped: &str) -> String {
    match lang {
        Some(Lang::Python) => code_with_strings_stripped
            .split('#')
            .next()
            .unwrap_or(code_with_strings_stripped)
            .trim()
            .to_string(),
        Some(Lang::Rust | Lang::JavaScript | Lang::TypeScript | Lang::Go) => {
            code_with_strings_stripped
                .split("//")
                .next()
                .unwrap_or(code_with_strings_stripped)
                .trim()
                .to_string()
        }
        None => code_with_strings_stripped.to_string(),
    }
}

fn collect_string_ranges(lang: Lang, node: Node, out: &mut Vec<(usize, usize)>) {
    let kind = node.kind();
    let is_string = match lang {
        Lang::Python => kind == "string",
        Lang::Rust => kind == "string_literal" || kind == "raw_string_literal",
        Lang::JavaScript | Lang::TypeScript => kind == "string" || kind == "template_string",
        Lang::Go => kind == "interpreted_string_literal" || kind == "raw_string_literal",
    };

    if is_string {
        let mut interps = Vec::new();
        if matches!(lang, Lang::Python | Lang::JavaScript | Lang::TypeScript) {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if matches!(child.kind(), "interpolation" | "template_substitution") {
                    interps.push(child);
                }
            }
        }
        if interps.is_empty() {
            out.push((node.start_byte(), node.end_byte()));
        } else {
            let mut cur = node.start_byte();
            for interp in interps {
                if interp.start_byte() > cur {
                    out.push((cur, interp.start_byte()));
                }
                collect_string_ranges(lang, interp, out);
                cur = interp.end_byte();
            }
            if node.end_byte() > cur {
                out.push((cur, node.end_byte()));
            }
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_string_ranges(lang, child, out);
    }
}

/// Replace string literal contents with empty quotes so regex-based code checks
/// don't false-positive on messages/regexes containing `"todo!()"` or `"console.log()"`.
fn strip_string_literals(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Rust raw string r#"..."# or r"..."
        if b == b'r' && i + 1 < bytes.len() && (bytes[i + 1] == b'"' || bytes[i + 1] == b'#') {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                out.push_str("\"\"");
                j += 1;
                while j < bytes.len() {
                    if bytes[j] == b'"' {
                        let mut k = 0;
                        while k < hashes && j + 1 + k < bytes.len() && bytes[j + 1 + k] == b'#' {
                            k += 1;
                        }
                        if k == hashes {
                            j += 1 + hashes;
                            break;
                        }
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            let quote = b;
            out.push(quote as char);
            out.push(quote as char);
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if let Some(ch) = line[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn extract_signatures(lang: Lang, source: &str) -> BTreeMap<String, FnSignature> {
    let mut map = BTreeMap::new();
    let mut parser = Parser::new();
    if parser.set_language(&ts_language(lang)).is_err() {
        return map;
    }
    let Some(tree) = parser.parse(source, None) else {
        return map;
    };
    let bytes = source.as_bytes();
    let mut stack = vec![tree.root_node()];

    while let Some(node) = stack.pop() {
        if lang == Lang::Rust && node.kind() == "mod_item" && has_rust_cfg_test_attr(node, bytes) {
            continue;
        }
        if let Some(sig) = extract_fn_signature(lang, node, bytes) {
            let key = scoped_signature_key(lang, node, &sig.name, bytes);
            map.entry(key).or_insert(sig);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    map
}

fn scoped_signature_key(lang: Lang, node: Node, name: &str, bytes: &[u8]) -> String {
    let mut cur = node.parent();
    while let Some(p) = cur {
        let pk = p.kind();
        let owner = match (lang, pk) {
            (Lang::Python, "class_definition")
            | (Lang::JavaScript | Lang::TypeScript, "class_declaration" | "class") => p
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(bytes).ok())
                .map(|s| s.trim().to_string()),
            (Lang::Rust, "impl_item") => p
                .child_by_field_name("type")
                .and_then(|n| n.utf8_text(bytes).ok())
                .map(collapse_ws),
            _ => None,
        };
        if let Some(o) = owner {
            if !o.is_empty() {
                return format!("{}::{}", o, name);
            }
        }
        cur = p.parent();
    }
    if lang == Lang::Go && node.kind() == "method_declaration" {
        if let Some(recv) = node
            .child_by_field_name("receiver")
            .and_then(|n| n.utf8_text(bytes).ok())
        {
            return format!("{}::{}", collapse_ws(recv), name);
        }
    }
    name.to_string()
}

fn extract_fn_signature(lang: Lang, node: Node, bytes: &[u8]) -> Option<FnSignature> {
    let name = extract_fn_name(lang, node, bytes)?;
    let line = node.start_position().row + 1;
    let is_public = is_node_public(lang, node, &name, bytes);

    let params_node = node
        .child_by_field_name("parameters")
        .or_else(|| node.child_by_field_name("formal_parameters"));

    let mut params = Vec::new();
    if let Some(pn) = params_node {
        let mut cursor = pn.walk();
        for child in pn.named_children(&mut cursor) {
            let ck = child.kind();
            if ck == "comment" {
                continue;
            }
            let raw_text = child.utf8_text(bytes).unwrap_or("").trim();
            if raw_text.is_empty() {
                continue;
            }
            let normalized = collapse_ws(raw_text);
            let has_default = match lang {
                Lang::Python => {
                    ck == "default_parameter"
                        || ck == "typed_default_parameter"
                        || normalized.contains('=')
                }
                Lang::JavaScript | Lang::TypeScript => {
                    ck == "assignment_pattern"
                        || ck == "optional_parameter"
                        || normalized.contains('=')
                        || normalized.contains("?:")
                }
                Lang::Rust | Lang::Go => false,
            };
            params.push(ParamInfo {
                text: normalized,
                has_default,
            });
        }
    }

    let return_type = node
        .child_by_field_name("return_type")
        .or_else(|| node.child_by_field_name("result"))
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(collapse_ws)
        .filter(|s| !s.is_empty());

    Some(FnSignature {
        name,
        params,
        return_type,
        is_public,
        line,
    })
}

fn is_node_public(lang: Lang, node: Node, name: &str, bytes: &[u8]) -> bool {
    match lang {
        Lang::Python => !name.starts_with('_') || name == "__init__",
        Lang::Rust => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "visibility_modifier" {
                    let txt = child.utf8_text(bytes).unwrap_or("");
                    if txt.starts_with("pub") {
                        return true;
                    }
                }
            }
            false
        }
        Lang::JavaScript | Lang::TypeScript => {
            if let Some(parent) = node.parent() {
                if parent.kind() == "export_statement" {
                    return true;
                }
            }
            if node.kind() == "method_definition" {
                let txt = node.utf8_text(bytes).unwrap_or("");
                return !name.starts_with('_')
                    && !name.starts_with('#')
                    && !txt.trim_start().starts_with("private ");
            }
            false
        }
        Lang::Go => name.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
    }
}

fn detect_breaking_signature(old: &FnSignature, new: &FnSignature) -> Option<String> {
    let old_req = old.params.iter().filter(|p| !p.has_default).count();
    let new_req = new.params.iter().filter(|p| !p.has_default).count();

    let mut reasons = Vec::new();

    if new_req > old_req {
        reasons.push(format!("required params {} -> {}", old_req, new_req));
    } else if new.params.len() < old.params.len() {
        reasons.push(format!(
            "params removed {} -> {}",
            old.params.len(),
            new.params.len()
        ));
    } else {
        for (o, n) in old.params.iter().zip(new.params.iter()) {
            let o_base = o.text.split('=').next().unwrap_or(&o.text).trim();
            let n_base = n.text.split('=').next().unwrap_or(&n.text).trim();
            if o_base != n_base {
                reasons.push(format!("param `{}` -> `{}`", o.text, n.text));
                break;
            }
        }
    }

    if old.return_type != new.return_type {
        let o_ret = old.return_type.as_deref().unwrap_or("none");
        let n_ret = new.return_type.as_deref().unwrap_or("none");
        reasons.push(format!("return {} -> {}", o_ret, n_ret));
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[allow(clippy::too_many_arguments)]
fn analyze_ast(
    rel_path: &str,
    lang: Lang,
    source: &str,
    is_test: bool,
    added_lines: &BTreeSet<usize>,
    findings: &mut Vec<Finding>,
    changed_symbols: &mut Vec<(String, String)>,
    body_fingerprints: &mut Vec<BodyFingerprint>,
    diff_ctx: &mut DiffContext,
) {
    let mut parser = Parser::new();
    if parser.set_language(&ts_language(lang)).is_err() {
        return;
    }
    let Some(tree) = parser.parse(source, None) else {
        return;
    };

    let bytes = source.as_bytes();
    let assert_re = Regex::new(ASSERT_PATTERN).unwrap();
    let py_fallback_re =
        Regex::new(r"^return\s+(None|False|True|\{\}|\[\]|''|\x22\x22|0)\s*$").unwrap();
    let js_fallback_re =
        Regex::new(r"^return(\s+(null|undefined|false|true|\{\}|\[\]|''|\x22\x22|0))?\s*;?$")
            .unwrap();

    // Collect file-level module mocks in JS/TS tests (e.g. `jest.mock('../src/auth')`, `vi.mock('./billing')`)
    let file_mocked_modules = if is_test && matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        extract_js_file_mocked_modules(source)
    } else {
        Vec::new()
    };

    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let start_line = node.start_position().row + 1;
        let end_line = node.end_position().row + 1;
        let touches_diff = (start_line..=end_line).any(|l| added_lines.contains(&l));

        // 1. Empty catch & silent fallback catch detection via AST
        if touches_diff {
            match (lang, kind) {
                (Lang::Python, "except_clause") => {
                    let txt = node.utf8_text(bytes).unwrap_or("");
                    let body_lines: Vec<&str> = txt
                        .lines()
                        .skip(1)
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty() && !s.starts_with('#'))
                        .collect();
                    if body_lines.len() == 1
                        && (body_lines[0] == "pass" || body_lines[0] == "...")
                    {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            category: Category::SilentSlop,
                            file: rel_path.to_string(),
                            line: start_line,
                            rule: "slop/empty-catch".into(),
                            message: "Empty catch/except block silently swallows errors".into(),
                        });
                    } else if body_lines.len() == 1 && py_fallback_re.is_match(body_lines[0]) {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            category: Category::SilentSlop,
                            file: rel_path.to_string(),
                            line: start_line,
                            rule: "slop/silent-fallback-catch".into(),
                            message: format!(
                                "Except block silently returns fallback (`{}`) without logging or re-raising",
                                body_lines[0]
                            ),
                        });
                    }
                }
                (Lang::JavaScript | Lang::TypeScript, "catch_clause") => {
                    if let Some(body) = node.child_by_field_name("body") {
                        let named_stmts: Vec<Node> = {
                            let mut c = body.walk();
                            body.named_children(&mut c)
                                .filter(|n| n.kind() != "comment")
                                .collect()
                        };
                        if named_stmts.is_empty() {
                            findings.push(Finding {
                                severity: Severity::Warning,
                                category: Category::SilentSlop,
                                file: rel_path.to_string(),
                                line: start_line,
                                rule: "slop/empty-catch".into(),
                                message: "Empty catch/except block silently swallows errors".into(),
                            });
                        } else if named_stmts.len() == 1
                            && named_stmts[0].kind() == "return_statement"
                        {
                            let ret_txt = named_stmts[0].utf8_text(bytes).unwrap_or("").trim();
                            if js_fallback_re.is_match(ret_txt) {
                                findings.push(Finding {
                                    severity: Severity::Warning,
                                    category: Category::SilentSlop,
                                    file: rel_path.to_string(),
                                    line: start_line,
                                    rule: "slop/silent-fallback-catch".into(),
                                    message: format!(
                                        "Catch block silently returns fallback (`{}`) without logging or rethrowing",
                                        ret_txt
                                    ),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // 2. JS/TS test('...', () => { ... }) / it('...', () => { ... }) test-theater analysis
        if is_test
            && touches_diff
            && matches!(lang, Lang::JavaScript | Lang::TypeScript)
            && kind == "call_expression"
        {
            if let Some((test_label, body_txt)) = extract_js_test_call(node, bytes) {
                if !assert_re.is_match(body_txt) {
                    findings.push(Finding {
                        severity: Severity::Blocker,
                        category: Category::TestTheater,
                        file: rel_path.to_string(),
                        line: start_line,
                        rule: "test-theater/empty-test".into(),
                        message: format!("Test `{}` contains 0 assertions", test_label),
                    });
                } else if is_mock_testing_mock(
                    lang,
                    &test_label,
                    body_txt,
                    "",
                    &file_mocked_modules,
                    diff_ctx,
                ) {
                    findings.push(Finding {
                        severity: Severity::Blocker,
                        category: Category::TestTheater,
                        file: rel_path.to_string(),
                        line: start_line,
                        rule: "test-theater/mock-testing-mock".into(),
                        message: format!(
                            "Test `{}` only asserts on mocked target/mock without verifying real behavior",
                            test_label
                        ),
                    });
                }
            }
        }

        // 3. Function/method definitions: empty tests, mock-testing-mock, stubs, blast radius, duplicate AST hash
        if let Some(name) = extract_fn_name(lang, node, bytes) {
            if touches_diff {
                let in_rust_inline_test =
                    lang == Lang::Rust && is_inside_rust_cfg_test(node, bytes);
                let node_is_test = is_test || in_rust_inline_test;
                let is_test_fn = (is_test
                    && (name.starts_with("test")
                        || name.starts_with("Test")
                        || (lang == Lang::Rust && has_rust_test_attr(node, bytes))))
                    || (lang == Lang::Rust && has_rust_test_attr(node, bytes));
                if is_test_fn {
                    let txt = node.utf8_text(bytes).unwrap_or("");
                    let decorator_src = if lang == Lang::Python {
                        node.parent()
                            .filter(|p| p.kind() == "decorated_definition")
                            .and_then(|p| p.utf8_text(bytes).ok())
                            .unwrap_or("")
                    } else {
                        ""
                    };
                    if !assert_re.is_match(txt) {
                        findings.push(Finding {
                            severity: Severity::Blocker,
                            category: Category::TestTheater,
                            file: rel_path.to_string(),
                            line: start_line,
                            rule: "test-theater/empty-test".into(),
                            message: format!("Test `{}` contains 0 assertions", name),
                        });
                    } else if is_mock_testing_mock(
                        lang,
                        &name,
                        txt,
                        decorator_src,
                        &file_mocked_modules,
                        diff_ctx,
                    ) {
                        findings.push(Finding {
                            severity: Severity::Blocker,
                            category: Category::TestTheater,
                            file: rel_path.to_string(),
                            line: start_line,
                            rule: "test-theater/mock-testing-mock".into(),
                            message: format!(
                                "Test `{}` only asserts on mocked target/mock without verifying real behavior",
                                name
                            ),
                        });
                    }
                } else if !node_is_test {
                    diff_ctx.modified_symbols.insert(name.clone());

                    if !is_generic_symbol_name(&name) {
                        changed_symbols.push((rel_path.to_string(), name.clone()));
                    }

                    // Placeholder / stub function body detection via AST
                    if is_placeholder_function_body(lang, node, &name, bytes) {
                        let already_flagged = findings.iter().any(|f| {
                            f.file == rel_path
                                && f.rule == "slop/unfinished-stub"
                                && f.line >= start_line
                                && f.line <= end_line
                        });
                        if !already_flagged {
                            findings.push(Finding {
                                severity: Severity::Warning,
                                category: Category::SilentSlop,
                                file: rel_path.to_string(),
                                line: start_line,
                                rule: "slop/unfinished-stub".into(),
                                message: format!(
                                    "Function `{}` has an empty or placeholder stub body",
                                    name
                                ),
                            });
                        }
                    }

                    if let Some(body) = node.child_by_field_name("body") {
                        let span_lines = end_line.saturating_sub(start_line) + 1;
                        let (hash, named_count) = structural_ast_hash(body);
                        if named_count >= 15 && span_lines >= 4 {
                            body_fingerprints.push(BodyFingerprint {
                                lang,
                                hash,
                                file: rel_path.to_string(),
                                line: start_line,
                                name,
                            });
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn is_placeholder_function_body(lang: Lang, node: Node, name: &str, bytes: &[u8]) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    match lang {
        Lang::Python => {
            // Skip @abstractmethod / @overload / Protocol stubs
            if let Some(parent) = node.parent() {
                if parent.kind() == "decorated_definition" {
                    let dec_txt = parent.utf8_text(bytes).unwrap_or("");
                    if dec_txt.contains("@abstractmethod") || dec_txt.contains("@overload") {
                        return false;
                    }
                }
            }
            let mut cursor = body.walk();
            let stmts: Vec<Node> = body
                .named_children(&mut cursor)
                .filter(|n| n.kind() != "comment")
                .collect();
            // Filter out leading docstring expression_statement containing only a string
            let meaningful: Vec<Node> = stmts
                .into_iter()
                .filter(|n| {
                    if n.kind() == "expression_statement" {
                        if let Some(ch) = n.named_child(0) {
                            if ch.kind() == "string" {
                                return false;
                            }
                        }
                    }
                    true
                })
                .collect();
            if meaningful.len() != 1 {
                return false;
            }
            let only = meaningful[0];
            let txt = only.utf8_text(bytes).unwrap_or("").trim();
            only.kind() == "pass_statement"
                || txt == "pass"
                || txt == "..."
                || txt.starts_with("raise NotImplementedError")
        }
        Lang::JavaScript | Lang::TypeScript => {
            if name == "constructor" {
                return false;
            }
            let mut cursor = body.walk();
            let named_stmts: Vec<Node> = body
                .named_children(&mut cursor)
                .filter(|n| n.kind() != "comment")
                .collect();
            named_stmts.is_empty()
        }
        Lang::Go => {
            let mut cursor = body.walk();
            let named_stmts: Vec<Node> = body
                .named_children(&mut cursor)
                .filter(|n| n.kind() != "comment")
                .collect();
            named_stmts.is_empty()
        }
        Lang::Rust => false, // Rust `todo!()` / `unimplemented!()` handled by line check
    }
}

fn extract_js_file_mocked_modules(source: &str) -> Vec<String> {
    let re = Regex::new(r#"\b(?:jest|vi)\.mock\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap();
    let mut out = Vec::new();
    for cap in re.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            let raw = m.as_str();
            let stem = Path::new(raw)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(raw);
            if !stem.is_empty() {
                out.push(stem.to_string());
            }
        }
    }
    out
}

fn has_rust_test_attr(node: Node, bytes: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(sib) = prev {
        if sib.kind() == "attribute_item" {
            let txt = sib.utf8_text(bytes).unwrap_or("");
            if txt.contains("test") {
                return true;
            }
            prev = sib.prev_sibling();
        } else {
            break;
        }
    }
    false
}

fn extract_js_test_call<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<(String, &'a str)> {
    let func = node.child_by_field_name("function")?;
    let func_txt = func.utf8_text(bytes).ok()?.trim();
    if !matches!(func_txt, "test" | "it" | "test.only" | "it.only") {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let named_args: Vec<Node> = args.named_children(&mut cursor).collect();
    if named_args.len() < 2 {
        return None;
    }
    let label = named_args[0]
        .utf8_text(bytes)
        .ok()?
        .trim_matches(|c| c == '\'' || c == '"' || c == '`')
        .to_string();
    let callback = named_args[1];
    if !matches!(
        callback.kind(),
        "arrow_function" | "function_expression" | "function"
    ) {
        return None;
    }
    let body_txt = callback.utf8_text(bytes).ok()?;
    Some((label, body_txt))
}

/// High-precision, diff-aware mock-testing-mock detector:
/// 1. Pure mock-on-mock: test creates mock variable(s), invokes them, and calls ZERO real functions.
/// 2. Diff-aware / SUT-mocking: test mocks a symbol/module modified in the git diff (or the exact
///    function being tested) AND has zero behavioral assertions on real outputs/state.
/// Legitimate DI tests that mock a dependency (e.g. mailer/db/logger) while exercising real code
/// are NOT flagged.
fn is_mock_testing_mock(
    lang: Lang,
    test_name: &str,
    test_src: &str,
    decorator_src: &str,
    file_mocked_modules: &[String],
    diff_ctx: &DiffContext,
) -> bool {
    let mock_assign_re = match lang {
        Lang::Python => Regex::new(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:unittest\.mock\.)?(?:MagicMock|Mock|AsyncMock|create_autospec|mocker\.MagicMock|mocker\.Mock|mocker\.patch|mock\.patch)\s*\(",
        )
        .unwrap(),
        Lang::JavaScript | Lang::TypeScript => Regex::new(
            r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:jest\.fn|vi\.fn|sinon\.stub|sinon\.spy|jest\.spyOn|vi\.spyOn|createMock)\s*\(",
        )
        .unwrap(),
        _ => return false,
    };
    let patch_as_re =
        Regex::new(r"\bwith\s+.*patch\s*\([^)]*\)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();

    let mut mock_vars: BTreeSet<String> = BTreeSet::new();
    for cap in mock_assign_re.captures_iter(test_src) {
        if let Some(m) = cap.get(1) {
            mock_vars.insert(m.as_str().to_string());
        }
    }
    for cap in patch_as_re.captures_iter(test_src) {
        if let Some(m) = cap.get(1) {
            mock_vars.insert(m.as_str().to_string());
        }
    }

    // In Python, `@patch(...)` injects mock parameters into `def test_foo(mock_bar):`
    let has_patch_decorator =
        lang == Lang::Python && (decorator_src.contains("patch(") || decorator_src.contains("patch.object("));
    if has_patch_decorator {
        let def_params_re = Regex::new(r"def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)").unwrap();
        if let Some(cap) = def_params_re.captures(test_src) {
            if let Some(params_m) = cap.get(1) {
                for p in params_m.as_str().split(',') {
                    let pname = p.split(':').next().unwrap_or("").split('=').next().unwrap_or("").trim();
                    if !pname.is_empty() && pname != "self" && pname != "cls" {
                        mock_vars.insert(pname.to_string());
                    }
                }
            }
        }
    }

    // Extract mocked symbol targets (e.g. `@patch("src.auth.verify_token")` -> "verify_token",
    // `jest.spyOn(auth, "verifyToken")` -> "verifyToken") and whole-module mocks (`jest.mock("../src/auth")` -> "auth").
    let mut mocked_symbols: BTreeSet<String> = BTreeSet::new();
    let mut mocked_modules: BTreeSet<String> = file_mocked_modules.iter().cloned().collect();

    let combined_src = if decorator_src.is_empty() {
        test_src.to_string()
    } else {
        format!("{}\n{}", decorator_src, test_src)
    };

    if lang == Lang::Python {
        let py_patch_target_re =
            Regex::new(r#"\bpatch(?:\.object)?\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*,\s*)?['"]([^'"]+)['"]"#)
                .unwrap();
        for cap in py_patch_target_re.captures_iter(&combined_src) {
            if let Some(m) = cap.get(1) {
                let target = m.as_str();
                if let Some(last) = target.rsplit('.').next() {
                    if !last.is_empty() {
                        mocked_symbols.insert(last.to_string());
                    }
                }
            }
        }
        let py_monkeypatch_re =
            Regex::new(r#"\bmonkeypatch\.setattr\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*['"]([^'"]+)['"]"#)
                .unwrap();
        for cap in py_monkeypatch_re.captures_iter(&combined_src) {
            if let Some(m) = cap.get(1) {
                mocked_symbols.insert(m.as_str().to_string());
            }
        }
    } else if matches!(lang, Lang::JavaScript | Lang::TypeScript) {
        let js_spy_re =
            Regex::new(r#"\b(?:jest|vi)\.spyOn\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*['"`]([^'"`]+)['"`]"#)
                .unwrap();
        for cap in js_spy_re.captures_iter(&combined_src) {
            if let Some(m) = cap.get(2) {
                mocked_symbols.insert(m.as_str().to_string());
            }
        }
        let js_mock_re = Regex::new(r#"\b(?:jest|vi)\.mock\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap();
        for cap in js_mock_re.captures_iter(&combined_src) {
            if let Some(m) = cap.get(1) {
                let stem = Path::new(m.as_str())
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(m.as_str());
                if !stem.is_empty() {
                    mocked_modules.insert(stem.to_string());
                }
            }
        }
    }

    // Track variables assigned directly from calling a mock or a mocked target symbol.
    let assign_call_re = Regex::new(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][A-Za-z0-9_$]*)(?:\.([A-Za-z_$][A-Za-z0-9_$]*))*\s*\(",
    )
    .unwrap();
    let mut mock_derived_vars = mock_vars.clone();
    for cap in assign_call_re.captures_iter(test_src) {
        if let (Some(lhs), Some(rhs_root)) = (cap.get(1), cap.get(2)) {
            let rhs_method = cap.get(3).map(|m| m.as_str()).unwrap_or("");
            if mock_derived_vars.contains(rhs_root.as_str())
                || mocked_symbols.contains(rhs_root.as_str())
                || mocked_symbols.contains(rhs_method)
                || mocked_modules.contains(rhs_root.as_str())
            {
                mock_derived_vars.insert(lhs.as_str().to_string());
            }
        }
    }

    // --- Path 1: Pure mock-on-mock (zero real functions invoked) ---
    if !mock_vars.is_empty() {
        let call_re = Regex::new(
            r"(?m)(?:^|[^.\w])([A-Za-z_$][A-Za-z0-9_$]*)(?:\.([A-Za-z_$][A-Za-z0-9_$]*))*\s*\(",
        )
        .unwrap();

        let mut has_mock_call = false;
        let mut has_real_call = false;
        for line in test_src.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("//")
                || trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with('@')
            {
                continue;
            }
            for cap in call_re.captures_iter(trimmed) {
                let root = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if mock_derived_vars.contains(root) {
                    has_mock_call = true;
                    continue;
                }
                if is_test_or_mock_infra_ident(root) {
                    continue;
                }
                has_real_call = true;
                break;
            }
            if has_real_call {
                break;
            }
        }
        if has_mock_call && !has_real_call {
            return true;
        }
    }

    // --- Path 2: Diff-aware / SUT-mocking with zero behavioral assertions on real outputs/state ---
    let test_name_lower = test_name.to_ascii_lowercase();
    let stripped_test_name = test_name_lower
        .strip_prefix("test_")
        .or_else(|| test_name_lower.strip_prefix("test"))
        .unwrap_or(&test_name_lower);

    let mocks_diff_or_sut = mocked_symbols.iter().any(|sym| {
        let sym_lower = sym.to_ascii_lowercase();
        diff_ctx.modified_symbols.contains(sym)
            || (sym_lower.len() >= 4 && stripped_test_name.contains(&sym_lower))
    }) || mocked_modules.iter().any(|m| {
        let m_lower = m.to_ascii_lowercase();
        diff_ctx.modified_modules.contains(m)
            || (m_lower.len() >= 4 && stripped_test_name.contains(&m_lower))
    });

    if !mocks_diff_or_sut {
        return false;
    }

    // Check whether the test has ZERO behavioral assertions on real outputs/state.
    let assert_line_re = Regex::new(
        r"\b(assert|expect\(|assertEqual|assertTrue|assertFalse|assertRaises)\b|\.assert_(called|not_called|any_call)",
    )
    .unwrap();
    let mock_matcher_re = Regex::new(
        r"(\.assert_(?:called|called_once|called_with|called_once_with|any_call|not_called)\b|\.(?:toHaveBeenCalled|toHaveBeenCalledWith|toHaveBeenCalledTimes|toHaveReturned|toHaveReturnedWith|calledOnce|calledWith)\b)",
    )
    .unwrap();
    let ident_re = Regex::new(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b").unwrap();

    let mut mock_assertions = 0usize;
    let mut real_assertions = 0usize;

    for line in test_src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if !assert_line_re.is_match(trimmed) {
            continue;
        }
        if mock_matcher_re.is_match(trimmed) {
            mock_assertions += 1;
            continue;
        }
        // Check if this assertion only references mock/mock-derived variables (no real output/state)
        let code_only = strip_string_literals(trimmed);
        let references_mock_derived = ident_re.captures_iter(&code_only).any(|c| {
            c.get(1)
                .is_some_and(|m| mock_derived_vars.contains(m.as_str()))
        });
        if references_mock_derived {
            mock_assertions += 1;
        } else {
            real_assertions += 1;
        }
    }

    mock_assertions > 0 && real_assertions == 0
}

fn is_test_or_mock_infra_ident(ident: &str) -> bool {
    matches!(
        ident,
        "MagicMock"
            | "Mock"
            | "AsyncMock"
            | "create_autospec"
            | "patch"
            | "mock"
            | "mocker"
            | "monkeypatch"
            | "unittest"
            | "pytest"
            | "jest"
            | "vi"
            | "sinon"
            | "createMock"
            | "expect"
            | "assert"
            | "assertEqual"
            | "assertTrue"
            | "assertFalse"
            | "assertRaises"
            | "len"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "set"
            | "tuple"
            | "range"
            | "print"
            | "Object"
            | "Array"
            | "JSON"
            | "Promise"
            | "Number"
            | "String"
            | "Boolean"
            | "Error"
            | "console"
            | "test"
            | "it"
            | "describe"
            | "beforeEach"
            | "afterEach"
            | "if"
            | "for"
            | "while"
            | "with"
            | "return"
            | "await"
            | "async"
            | "function"
    )
}

/// Deterministic FNV-1a 64-bit structural AST hash of a subtree (normalizing identifiers & literals).
fn structural_ast_hash(root: Node) -> (u64, usize) {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn mix(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h ^= u64::from(b);
            *h = h.wrapping_mul(FNV_PRIME);
        }
    }

    fn walk(node: Node, h: &mut u64, count: &mut usize) {
        if !node.is_named() || node.kind() == "comment" {
            return;
        }
        *count += 1;
        mix(h, b"(");
        mix(h, node.kind().as_bytes());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, h, count);
        }
        mix(h, b")");
    }

    let mut h = FNV_OFFSET;
    let mut count = 0usize;
    walk(root, &mut h, &mut count);
    (h, count)
}

fn detect_duplicate_bodies(fingerprints: &[BodyFingerprint], findings: &mut Vec<Finding>) {
    let mut groups: BTreeMap<(Lang, u64), Vec<&BodyFingerprint>> = BTreeMap::new();
    for fp in fingerprints {
        groups.entry((fp.lang, fp.hash)).or_default().push(fp);
    }
    for group in groups.values() {
        if group.len() < 2 {
            continue;
        }
        let first = group[0];
        for dup in group.iter().skip(1) {
            if dup.file == first.file && dup.line == first.line {
                continue;
            }
            findings.push(Finding {
                severity: Severity::Warning,
                category: Category::SilentSlop,
                file: dup.file.clone(),
                line: dup.line,
                rule: "slop/duplicate-code".into(),
                message: format!(
                    "Function `{}` has identical AST structure to `{}` ({}:{})",
                    dup.name, first.name, first.file, first.line
                ),
            });
        }
    }
}

fn extract_fn_name(lang: Lang, node: Node, bytes: &[u8]) -> Option<String> {
    let kind = node.kind();
    let is_fn = match lang {
        Lang::Python => kind == "function_definition",
        Lang::Rust => kind == "function_item",
        Lang::JavaScript | Lang::TypeScript => {
            kind == "function_declaration" || kind == "method_definition"
        }
        Lang::Go => kind == "function_declaration" || kind == "method_declaration",
    };
    if !is_fn {
        return None;
    }
    node.child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
        .map(|s| s.to_string())
}

fn is_skipped_dir_name(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | ".next"
            | "dist"
            | "build"
            | "out"
            | "vendor"
            | "__pycache__"
            | ".venv"
            | "venv"
            | "coverage"
            | ".turbo"
            | ".cache"
            | ".svelte-kit"
            | ".nuxt"
            | ".output"
            | ".vercel"
            | ".wrangler"
            | "storybook-static"
    )
}

fn is_skipped_rel_path(rel_str: &str, config: &Config) -> bool {
    if config.is_ignored(rel_str) {
        return true;
    }
    let lower = rel_str.to_ascii_lowercase();
    if lower.ends_with(".min.js") || lower.ends_with(".min.ts") || lower.ends_with(".bundle.js") {
        return true;
    }
    rel_str.split('/').any(is_skipped_dir_name)
}

fn collect_repo_source_files(repo_root: &Path, config: &Config) -> Vec<(String, std::path::PathBuf)> {
    const MAX_SCAN_FILE_BYTES: u64 = 512 * 1024;

    // Fast path: if this is a git repository, `git ls-files` respects `.gitignore`
    // natively and avoids walking untracked build outputs and dependency trees.
    if repo_root.join(".git").exists() {
        if let Ok(output) = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
            .output()
        {
            if output.status.success() {
                let mut files = Vec::new();
                for raw in output.stdout.split(|&b| b == 0) {
                    if raw.is_empty() {
                        continue;
                    }
                    let Ok(rel_raw) = std::str::from_utf8(raw) else {
                        continue;
                    };
                    let rel_str = rel_raw.replace('\\', "/");
                    if detect_lang(&rel_str).is_none() || is_skipped_rel_path(&rel_str, config) {
                        continue;
                    }
                    let full = repo_root.join(&rel_str);
                    if let Ok(meta) = fs::metadata(&full) {
                        if meta.is_file() && meta.len() <= MAX_SCAN_FILE_BYTES {
                            files.push((rel_str, full));
                        }
                    }
                }
                return files;
            }
        }
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(repo_root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !is_skipped_dir_name(&name)
        })
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(repo_root) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if detect_lang(&rel_str).is_none() || is_skipped_rel_path(&rel_str, config) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.len() <= MAX_SCAN_FILE_BYTES {
                files.push((rel_str, entry.path().to_path_buf()));
            }
        }
    }
    files
}

fn scan_repo_references(
    repo_root: &Path,
    changed: &[(String, String)],
    new_public: &[(String, String, usize)],
    config: &Config,
) -> (Vec<BlastEntry>, BTreeSet<String>) {
    if changed.is_empty() && new_public.is_empty() {
        return (Vec::new(), BTreeSet::new());
    }

    let mut unique_changed: BTreeMap<(String, String), Regex> = BTreeMap::new();
    for (file, sym) in changed {
        let key = (file.clone(), sym.clone());
        unique_changed.entry(key).or_insert_with(|| {
            Regex::new(&format!(r"\b{}\s*\(", regex::escape(sym))).unwrap()
        });
    }

    let mut unique_public: BTreeMap<String, Regex> = BTreeMap::new();
    for (_, sym, _) in new_public {
        unique_public.entry(sym.clone()).or_insert_with(|| {
            Regex::new(&format!(r"\b{}\b", regex::escape(sym))).unwrap()
        });
    }

    let mut callers_map: BTreeMap<(String, String), Vec<CallerRef>> = BTreeMap::new();
    let mut test_refs: BTreeSet<String> = BTreeSet::new();

    for (rel_str, full_path) in collect_repo_source_files(repo_root, config) {
        let Ok(content) = fs::read_to_string(&full_path) else {
            continue;
        };
        let is_test = is_test_path(&rel_str);
        // For Rust non-test source files, detect inline `#[cfg(test)]` modules so
        // inline unit tests count as real test coverage and test callers.
        let rust_inline_test_slice: Option<&str> =
            if !is_test && rel_str.ends_with(".rs") {
                content.find("#[cfg(test)]").map(|idx| &content[idx..])
            } else {
                None
            };
        let rust_prod_slice: Option<&str> =
            if !is_test && rel_str.ends_with(".rs") {
                content.find("#[cfg(test)]").map(|idx| &content[..idx])
            } else {
                None
            };

        for ((def_file, sym), re) in &unique_changed {
            if def_file == &rel_str {
                continue;
            }
            if !content.contains(sym.as_str()) {
                continue;
            }
            if re.is_match(&content) {
                let caller_is_test = is_test
                    || rust_prod_slice.is_some_and(|prod| !re.is_match(prod));
                callers_map
                    .entry((def_file.clone(), sym.clone()))
                    .or_default()
                    .push(CallerRef {
                        file: rel_str.clone(),
                        is_test: caller_is_test,
                    });
            }
        }

        if is_test {
            for (sym, re) in &unique_public {
                if content.contains(sym.as_str()) && re.is_match(&content) {
                    test_refs.insert(sym.clone());
                }
            }
        } else if let Some(inline_tests) = rust_inline_test_slice {
            for (sym, re) in &unique_public {
                if inline_tests.contains(sym.as_str()) && re.is_match(inline_tests) {
                    test_refs.insert(sym.clone());
                }
            }
        }
    }

    let blast = callers_map
        .into_iter()
        .map(|((file, symbol), callers)| BlastEntry {
            file,
            symbol,
            callers,
            signature_change: None,
            unupdated_callers: Vec::new(),
        })
        .collect();

    (blast, test_refs)
}

/// Standalone blast-radius query for a single symbol (used by MCP `yupp_blast_radius`).
pub fn compute_symbol_blast_radius(
    repo_root: &Path,
    symbol: &str,
    def_file: Option<&str>,
) -> BlastEntry {
    let def = def_file.unwrap_or("").to_string();
    let changed = vec![(def.clone(), symbol.to_string())];
    let config = Config::load(repo_root, None).unwrap_or_default();
    let (mut entries, _) = scan_repo_references(repo_root, &changed, &[], &config);
    entries.pop().unwrap_or(BlastEntry {
        file: def,
        symbol: symbol.to_string(),
        callers: Vec::new(),
        signature_change: None,
        unupdated_callers: Vec::new(),
    })
}
