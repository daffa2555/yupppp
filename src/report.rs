use crate::ast::{BlastEntry, Category, Finding, Severity};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Yupp,
    Hmm,
    Nope,
}

impl Verdict {
    pub fn from_counts(blockers: usize, warnings: usize, strict: bool) -> Self {
        if blockers > 0 || (strict && warnings > 0) {
            Verdict::Nope
        } else if warnings > 0 {
            Verdict::Hmm
        } else {
            Verdict::Yupp
        }
    }

    pub fn label(self, use_emoji: bool) -> &'static str {
        match (self, use_emoji) {
            (Verdict::Yupp, true) => "yupp 👌",
            (Verdict::Yupp, false) => "yupp [OK]",
            (Verdict::Hmm, true) => "hmm 🤔",
            (Verdict::Hmm, false) => "hmm [WARN]",
            (Verdict::Nope, true) => "nope ❌",
            (Verdict::Nope, false) => "nope [FAIL]",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: &'static str,
    pub verdict: Verdict,
    pub passed: bool,
    pub files_scanned: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
    pub elapsed_ms: u128,
    pub blockers: usize,
    pub warnings: usize,
    pub findings: Vec<Finding>,
    pub blast_radius: Vec<BlastEntry>,
}

struct AnsiPalette {
    reset: &'static str,
    bold: &'static str,
    dim: &'static str,
    bold_red: &'static str,
    bold_green: &'static str,
    bold_yellow: &'static str,
    bold_cyan: &'static str,
    yellow: &'static str,
}

impl AnsiPalette {
    fn new(use_color: bool) -> Self {
        if use_color {
            Self {
                reset: "\x1b[0m",
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                bold_red: "\x1b[1;31m",
                bold_green: "\x1b[1;32m",
                bold_yellow: "\x1b[1;33m",
                bold_cyan: "\x1b[1;36m",
                yellow: "\x1b[33m",
            }
        } else {
            Self {
                reset: "",
                bold: "",
                dim: "",
                bold_red: "",
                bold_green: "",
                bold_yellow: "",
                bold_cyan: "",
                yellow: "",
            }
        }
    }
}

pub fn render_terminal(report: &Report, use_emoji: bool) -> String {
    render_terminal_with_color(report, use_emoji, false)
}

pub fn render_terminal_with_color(report: &Report, use_emoji: bool, use_color: bool) -> String {
    let p = AnsiPalette::new(use_color);
    let mut out = String::new();
    out.push_str(&format!(
        "{}yupp v{}{} {}· scanned {} files (+{} -{}) in {}ms (0-LLM · Tree-sitter AST){}\n",
        p.bold,
        report.version,
        p.reset,
        p.dim,
        report.files_scanned,
        report.lines_added,
        report.lines_removed,
        report.elapsed_ms,
        p.reset
    ));

    let breaking: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == Category::BreakingChange)
        .collect();
    if !breaking.is_empty() {
        out.push_str(&format!(
            "\n{}[BREAKING CHANGES]{} {} finding(s)\n",
            p.bold_yellow,
            p.reset,
            breaking.len()
        ));
        for (i, f) in breaking.iter().enumerate() {
            out.push_str(&format!(
                "  {}{}.{} {}{}:{}{}  {} {}[{}]{}\n",
                p.dim,
                i + 1,
                p.reset,
                p.bold,
                f.file,
                f.line,
                p.reset,
                f.message,
                p.dim,
                f.rule,
                p.reset
            ));
        }
    }

    let theater: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == Category::TestTheater)
        .collect();
    if !theater.is_empty() {
        out.push_str(&format!(
            "\n{}[TEST THEATER]{} {} finding(s)\n",
            p.bold_red,
            p.reset,
            theater.len()
        ));
        for (i, f) in theater.iter().enumerate() {
            out.push_str(&format!(
                "  {}{}.{} {}{}:{}{}  {} {}[{}]{}\n",
                p.dim,
                i + 1,
                p.reset,
                p.bold,
                f.file,
                f.line,
                p.reset,
                f.message,
                p.dim,
                f.rule,
                p.reset
            ));
        }
    }

    let secrets: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == Category::SecretLeak)
        .collect();
    if !secrets.is_empty() {
        out.push_str(&format!(
            "\n{}[SECRET LEAK]{} {} blocker(s)\n",
            p.bold_red,
            p.reset,
            secrets.len()
        ));
        for (i, f) in secrets.iter().enumerate() {
            out.push_str(&format!(
                "  {}{}.{} {}{}:{}{}  {} {}[{}]{}\n",
                p.dim,
                i + 1,
                p.reset,
                p.bold,
                f.file,
                f.line,
                p.reset,
                f.message,
                p.dim,
                f.rule,
                p.reset
            ));
        }
    }

    if !report.blast_radius.is_empty() {
        out.push_str(&format!(
            "\n{}[BLAST RADIUS]{} {} modified symbol(s) with cross-file callers\n",
            p.bold_cyan,
            p.reset,
            report.blast_radius.len()
        ));
        for b in &report.blast_radius {
            let caller_list: Vec<String> = b
                .callers
                .iter()
                .map(|c| {
                    let mut tag = c.file.clone();
                    if c.is_test {
                        tag.push_str(" [TEST]");
                    }
                    if b.unupdated_callers.contains(&c.file) {
                        tag.push_str(" [NOT IN PR]");
                    }
                    tag
                })
                .collect();
            let has_test = b.callers.iter().any(|c| c.is_test);
            let cov = if has_test {
                String::new()
            } else {
                format!(" {}[NO TEST CALLER]{}", p.yellow, p.reset)
            };
            let sig = match &b.signature_change {
                Some(s) => format!(" {}[SIG CHANGED: {}]{}", p.bold_yellow, s, p.reset),
                None => String::new(),
            };
            out.push_str(&format!(
                "  • {}{}:{}{} {}({} callers){}{}{}\n    {}↳ {}{}\n",
                p.bold,
                b.file,
                b.symbol,
                p.reset,
                p.dim,
                b.callers.len(),
                p.reset,
                cov,
                sig,
                p.dim,
                caller_list.join(", "),
                p.reset
            ));
        }
    }

    let slop: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == Category::SilentSlop)
        .collect();
    if !slop.is_empty() {
        out.push_str(&format!(
            "\n{}[SILENT SLOP & HAZARDS]{} {} finding(s)\n",
            p.bold_yellow,
            p.reset,
            slop.len()
        ));
        for (i, f) in slop.iter().enumerate() {
            out.push_str(&format!(
                "  {}{}.{} {}{}:{}{}  {} {}[{}]{}\n",
                p.dim,
                i + 1,
                p.reset,
                p.bold,
                f.file,
                f.line,
                p.reset,
                f.message,
                p.dim,
                f.rule,
                p.reset
            ));
        }
    }

    out.push('\n');
    let label = report.verdict.label(use_emoji);
    match report.verdict {
        Verdict::Yupp => {
            out.push_str(&format!(
                "{}{}{}  {}({} blockers, {} warnings · {}ms){}\n",
                p.bold_green,
                label,
                p.reset,
                p.dim,
                report.blockers,
                report.warnings,
                report.elapsed_ms,
                p.reset
            ));
        }
        Verdict::Hmm => {
            out.push_str(&format!(
                "{}{}{}  {}({} blockers, {} warnings · {}ms){}\n",
                p.bold_yellow,
                label,
                p.reset,
                p.dim,
                report.blockers,
                report.warnings,
                report.elapsed_ms,
                p.reset
            ));
        }
        Verdict::Nope => {
            out.push_str(&format!(
                "{}{}{}  {}({} blockers, {} warnings · {}ms · exit 1){}\n",
                p.bold_red,
                label,
                p.reset,
                p.dim,
                report.blockers,
                report.warnings,
                report.elapsed_ms,
                p.reset
            ));
        }
    }

    out
}

pub fn render_pr_comment(report: &Report, use_emoji: bool) -> String {
    let verdict = report.verdict.label(use_emoji);

    let mut md = format!(
        "### {} — PR X-Ray (`{}ms`, 0-LLM)\n\n",
        verdict, report.elapsed_ms
    );
    md.push_str(&format!(
        "Scanned **{} files** (`+{}` / `-{}`) · **{} blockers** · **{} warnings**\n\n",
        report.files_scanned,
        report.lines_added,
        report.lines_removed,
        report.blockers,
        report.warnings
    ));

    if !report.findings.is_empty() {
        md.push_str("| Severity | Location | Rule | Detail |\n|---|---|---|---|\n");
        for f in &report.findings {
            let sev = match f.severity {
                Severity::Blocker => "BLOCKER",
                Severity::Warning => "WARN",
            };
            md.push_str(&format!(
                "| `{}` | `{}:{}` | `{}` | {} |\n",
                sev, f.file, f.line, f.rule, f.message
            ));
        }
        md.push('\n');
    }

    if !report.blast_radius.is_empty() {
        md.push_str("**Blast Radius**\n");
        for b in &report.blast_radius {
            let callers: Vec<&str> = b.callers.iter().map(|c| c.file.as_str()).collect();
            let sig_note = match &b.signature_change {
                Some(s) => format!(" _(breaking: {})_", s),
                None => String::new(),
            };
            md.push_str(&format!(
                "- `{}:{}`{} → {} caller(s): `{}`\n",
                b.file,
                b.symbol,
                sig_note,
                b.callers.len(),
                callers.join("`, `")
            ));
        }
    }

    md
}

/// Render a SARIF 2.1.0 report compatible with GitHub Code Scanning.
pub fn render_sarif(report: &Report) -> String {
    let mut rules_map: BTreeMap<String, Value> = BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();

    for f in &report.findings {
        let level = match f.severity {
            Severity::Blocker => "error",
            Severity::Warning => "warning",
        };
        rules_map.entry(f.rule.clone()).or_insert_with(|| {
            json!({
                "id": f.rule,
                "shortDescription": {
                    "text": rule_short_description(&f.rule)
                },
                "defaultConfiguration": {
                    "level": level
                }
            })
        });

        results.push(json!({
            "ruleId": f.rule,
            "level": level,
            "message": {
                "text": f.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file
                    },
                    "region": {
                        "startLine": f.line.max(1)
                    }
                }
            }]
        }));
    }

    let rules: Vec<Value> = rules_map.into_values().collect();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "yupp",
                    "version": report.version,
                    "informationUri": "https://github.com/yupp-cli/yupp",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}

fn rule_short_description(rule: &str) -> &'static str {
    match rule {
        "breaking/signature-changed" => "Public function signature changed incompatibly",
        "breaking/public-symbol-removed" => "Public symbol removed with active callers",
        "test-theater/assertions-removed" => "Test assertions reduced or deleted in diff",
        "test-theater/empty-test" => "Test function contains zero assertions",
        "test-theater/skipped-test" => "Test skipped or ignored in diff",
        "test-theater/trivial-assertion" => "Trivial tautology assertion that always passes",
        "test-theater/mock-testing-mock" => "Test only invokes and asserts on mocks without testing real code",
        "test-theater/untested-new-public" => "Newly added public function has zero test references",
        "slop/empty-catch" => "Empty catch/except block silently swallows errors",
        "slop/silent-fallback-catch" => "Catch/except block silently returns fallback sentinel",
        "slop/debug-leftover" => "Debug print or debugger breakpoint leftover",
        "slop/duplicate-code" => "Duplicate function body detected via AST structural hash",
        "slop/type-suppression" => "Compiler or type-checker suppression added",
        "slop/rust-unwrap" => "New .unwrap()/.expect() panic hazard introduced",
        "slop/unfinished-stub" => "Unfinished stub (todo!/unimplemented!/NotImplementedError)",
        r if r.starts_with("secret/") => "Hardcoded secret or credential pattern introduced",
        _ => "yupp static analysis finding",
    }
}
