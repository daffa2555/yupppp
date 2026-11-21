use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Instant;
use yupp::ast::{analyze_diff_with_options, AnalyzeOptions, Severity};
use yupp::config::{init_config, Config};
use yupp::diff::{parse_unified_diff, resolve_base_ref};
use yupp::mcp::run_mcp_stdio;
use yupp::report::{render_pr_comment, render_sarif, render_terminal, Report, Verdict};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Terminal,
    PrComment,
    Json,
    Sarif,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a .yupp.toml config file (and optionally install a git hook)
    Init {
        /// Overwrite existing .yupp.toml or git hook
        #[arg(long)]
        force: bool,

        /// Optionally install a git hook (pre-commit or pre-push)
        #[arg(long, value_name = "HOOK")]
        hook: Option<String>,

        /// Repository root directory
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    /// Run yupp as a native MCP server over JSON-RPC 2.0 stdio
    Mcp,
}

#[derive(Parser, Debug)]
#[command(
    name = "yupp",
    version,
    about = "0-LLM Rust CLI that catches AI test theater, silent slop, breaking changes, and PR blast radius in milliseconds"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Git diff range (e.g. main..HEAD). Defaults to unstaged working tree diff.
    range: Option<String>,

    /// Inspect staged changes (`git diff --cached`)
    #[arg(long)]
    staged: bool,

    /// Read unified diff from stdin instead of invoking git
    #[arg(long)]
    stdin: bool,

    /// Repository root directory
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Path to .yupp.toml config file (defaults to <repo>/.yupp.toml if present)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Fail with exit code 1 on warnings as well as blockers
    #[arg(long)]
    strict: bool,

    /// Disable emoji in output (ASCII only)
    #[arg(long)]
    no_emoji: bool,
}

fn read_diff(cli: &Cli) -> Result<String, String> {
    if cli.stdin {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {}", e))?;
        return Ok(buf);
    }

    let mut cmd = Command::new("git");
    cmd.current_dir(&cli.repo).arg("diff").arg("--unified=3");
    if cli.staged {
        cmd.arg("--cached");
    } else if let Some(ref r) = cli.range {
        cmd.arg(r);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("failed to run git diff: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Init { force, hook, repo } => {
                match init_config(&repo, force, hook.as_deref()) {
                    Ok(actions) => {
                        for a in actions {
                            println!("{}", a);
                        }
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        eprintln!("yupp init error: {}", e);
                        return ExitCode::from(2);
                    }
                }
            }
            Commands::Mcp => {
                if let Err(e) = run_mcp_stdio() {
                    eprintln!("yupp mcp error: {}", e);
                    return ExitCode::from(2);
                }
                return ExitCode::SUCCESS;
            }
        }
    }

    let started = Instant::now();

    let config = match Config::load(&cli.repo, cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("yupp config error: {}", e);
            return ExitCode::from(2);
        }
    };

    let raw_diff = match read_diff(&cli) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("yupp error: {}", e);
            return ExitCode::from(2);
        }
    };

    let base_ref = if cli.stdin {
        cli.range
            .as_deref()
            .and_then(|r| resolve_base_ref(Some(r), false, &cli.repo))
    } else {
        resolve_base_ref(cli.range.as_deref(), cli.staged, &cli.repo)
    };

    let files = parse_unified_diff(&raw_diff);
    let lines_added: usize = files.iter().map(|f| f.added.len()).sum();
    let lines_removed: usize = files.iter().map(|f| f.removed.len()).sum();

    let strict = cli.strict || config.strict.unwrap_or(false);
    let opts = AnalyzeOptions { base_ref, config };
    let (findings, blast_radius) = analyze_diff_with_options(&files, &cli.repo, &opts);
    let blockers = findings
        .iter()
        .filter(|f| f.severity == Severity::Blocker)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();

    let verdict = Verdict::from_counts(blockers, warnings, strict);
    let passed = verdict != Verdict::Nope;
    let report = Report {
        version: env!("CARGO_PKG_VERSION"),
        verdict,
        passed,
        files_scanned: files.len(),
        lines_added,
        lines_removed,
        elapsed_ms: started.elapsed().as_millis(),
        blockers,
        warnings,
        findings,
        blast_radius,
    };

    let use_emoji = !cli.no_emoji && std::env::var_os("NO_COLOR").is_none();
    match cli.format {
        Format::Terminal => print!("{}", render_terminal(&report, use_emoji)),
        Format::PrComment => print!("{}", render_pr_comment(&report, use_emoji)),
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
            );
        }
        Format::Sarif => {
            println!("{}", render_sarif(&report));
        }
    }

    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use yupp::ast::analyze_diff;

    fn make_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("yupp-test-{}-{}", label, nanos));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn catches_test_theater_and_secrets_and_slop() {
        let dir = make_temp_dir("theater");
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();

        fs::write(
            dir.join("tests/test_auth.py"),
            "def test_login():\n    x = 1\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/service.py"),
            "def verify_token():\n    try:\n        return True\n    except Exception:\n        pass\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/routes.py"),
            "def handle():\n    return verify_token()\n",
        )
        .unwrap();

        let sample_diff = "\
+++ b/tests/test_auth.py
@@ -1,3 +1,2 @@
-def test_login():
-    assert True == login()
+def test_login():
+    x = 1
+++ b/src/service.py
@@ -1,1 +1,5 @@
+def verify_token():
+    try:
+        return True
+    except Exception:
+        pass
";
        let files = parse_unified_diff(sample_diff);
        let (findings, blast) = analyze_diff(&files, &dir);

        assert!(findings.iter().any(|f| f.rule == "test-theater/assertions-removed"));
        assert!(findings.iter().any(|f| f.rule == "test-theater/empty-test"));
        assert!(findings.iter().any(|f| f.rule == "slop/empty-catch"));
        assert_eq!(blast.len(), 1);
        assert_eq!(blast[0].symbol, "verify_token");
        assert_eq!(blast[0].callers[0].file, "src/routes.py");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn clean_diff_passes_with_yupp_ok() {
        let dir = make_temp_dir("clean");
        let sample_diff = "\
+++ b/src/math.rs
@@ -1,1 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
";
        let files = parse_unified_diff(sample_diff);
        let (findings, _) = analyze_diff(&files, &dir);
        assert!(findings.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn catches_ts_empty_catch_and_rust_unwrap_and_secrets() {
        let dir = make_temp_dir("multi");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();

        fs::write(
            dir.join("src/client.ts"),
            "export function fetchUser() {\n  try {\n    return 1;\n  } catch (e) {}\n}\n",
        )
        .unwrap();
        let fake_key = format!("sk_{}_{}", "live", "51N9x8K2f9a8b7c6d5e4f3g2h1");
        fs::write(
            dir.join("src/parse.rs"),
            format!(
                "pub fn parse(s: &str) -> i32 {{\n    let k = \"{}\";\n    let _ = k;\n    s.parse().unwrap()\n}}\n",
                fake_key
            ),
        )
        .unwrap();
        fs::write(
            dir.join("tests/skip.test.ts"),
            "test.skip('broken case', () => { expect(1).toBe(1); });\n",
        )
        .unwrap();

        let sample_diff = format!(
            "\
+++ b/src/client.ts
@@ -1,1 +1,5 @@
+export function fetchUser() {{
+  try {{
+    return 1;
+  }} catch (e) {{}}
+}}
+++ b/src/parse.rs
@@ -1,1 +1,5 @@
+pub fn parse(s: &str) -> i32 {{
+    let k = \"{}\";
+    let _ = k;
+    s.parse().unwrap()
+}}
+++ b/tests/skip.test.ts
@@ -1,1 +1,1 @@
+test.skip('broken case', () => {{ expect(1).toBe(1); }});
",
            fake_key
        );
        let files = parse_unified_diff(&sample_diff);
        let (findings, _) = analyze_diff(&files, &dir);

        assert!(findings.iter().any(|f| f.rule == "slop/empty-catch"));
        assert!(findings.iter().any(|f| f.rule == "slop/rust-unwrap"));
        assert!(findings.iter().any(|f| f.rule == "secret/stripe"));
        assert!(findings.iter().any(|f| f.rule == "test-theater/skipped-test"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn renders_terminal_pr_comment_and_ascii_fallback() {
        // 1. Clean: 0 blockers, 0 warnings -> yupp 👌 / yupp [OK]
        let ok_rep = Report {
            version: "0.1.0",
            verdict: Verdict::from_counts(0, 0, false),
            passed: true,
            files_scanned: 2,
            lines_added: 12,
            lines_removed: 3,
            elapsed_ms: 4,
            blockers: 0,
            warnings: 0,
            findings: vec![],
            blast_radius: vec![],
        };
        assert_eq!(ok_rep.verdict, Verdict::Yupp);
        assert!(render_terminal(&ok_rep, true).contains("yupp 👌"));
        assert!(render_terminal(&ok_rep, false).contains("yupp [OK]"));
        assert!(render_pr_comment(&ok_rep, true).contains("### yupp 👌"));
        assert!(render_pr_comment(&ok_rep, false).contains("### yupp [OK]"));
        let ok_json: serde_json::Value = serde_json::to_value(&ok_rep).unwrap();
        assert_eq!(ok_json["verdict"], "yupp");

        // 2. Warnings only (non-strict): 0 blockers, >0 warnings -> hmm 🤔 / hmm [WARN]
        let warn_rep = Report {
            version: "0.1.0",
            verdict: Verdict::from_counts(0, 2, false),
            passed: true,
            files_scanned: 1,
            lines_added: 5,
            lines_removed: 0,
            elapsed_ms: 3,
            blockers: 0,
            warnings: 2,
            findings: vec![],
            blast_radius: vec![],
        };
        assert_eq!(warn_rep.verdict, Verdict::Hmm);
        assert!(render_terminal(&warn_rep, true).contains("hmm 🤔"));
        assert!(render_terminal(&warn_rep, false).contains("hmm [WARN]"));
        assert!(!render_terminal(&warn_rep, true).contains("exit 1"));
        assert!(render_pr_comment(&warn_rep, true).contains("### hmm 🤔"));
        assert!(render_pr_comment(&warn_rep, false).contains("### hmm [WARN]"));
        let warn_json: serde_json::Value = serde_json::to_value(&warn_rep).unwrap();
        assert_eq!(warn_json["verdict"], "hmm");

        // 3. Blockers (or --strict with warnings) -> nope ❌ / nope [FAIL]
        assert_eq!(Verdict::from_counts(0, 2, true), Verdict::Nope);
        let fail_rep = Report {
            version: "0.1.0",
            verdict: Verdict::from_counts(1, 1, false),
            passed: false,
            files_scanned: 1,
            lines_added: 5,
            lines_removed: 1,
            elapsed_ms: 3,
            blockers: 1,
            warnings: 1,
            findings: vec![],
            blast_radius: vec![],
        };
        assert_eq!(fail_rep.verdict, Verdict::Nope);
        assert!(render_terminal(&fail_rep, true).contains("nope ❌"));
        assert!(render_terminal(&fail_rep, false).contains("nope [FAIL]"));
        assert!(render_terminal(&fail_rep, true).contains("exit 1"));
        assert!(render_pr_comment(&fail_rep, true).contains("### nope ❌"));
        assert!(render_pr_comment(&fail_rep, false).contains("### nope [FAIL]"));
        let fail_json: serde_json::Value = serde_json::to_value(&fail_rep).unwrap();
        assert_eq!(fail_json["verdict"], "nope");
    }
}
