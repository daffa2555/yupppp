use serde_json::{json, Value};
use std::fs;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use yupp::ast::{analyze_diff_with_options, AnalyzeOptions, Severity};
use yupp::config::{init_config, Config, SeverityOverride};
use yupp::diff::{parse_unified_diff, resolve_base_ref, resolve_head_ref};
use yupp::mcp::run_mcp_io;
use yupp::report::{render_sarif, render_terminal, render_terminal_with_color, Report, Verdict};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn make_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("yupp-int-{}-{}-{}", label, nanos, seq));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to execute git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn init_git_repo(dir: &Path) {
    git(dir, &["init"]);
    git(dir, &["config", "user.email", "test@yupp.dev"]);
    git(dir, &["config", "user.name", "Yupp Test"]);
}

fn yupp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_yupp")
}

// =========================================================================
// Feature 1: Old-AST vs New-AST Breaking Signature Diff
// =========================================================================

#[test]
fn breaking_signature_change_with_unupdated_caller_is_conservative_warning() {
    let dir = make_temp_dir("breaking-unupdated");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/auth.py"),
        "def verify_token(token: str) -> bool:\n    return bool(token)\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/api.py"),
        "from auth import verify_token\n\ndef handle(t):\n    return verify_token(t)\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial"]);

    // Break public signature by adding required param `strict` and changing return type
    fs::write(
        dir.join("src/auth.py"),
        "def verify_token(token: str, strict: bool) -> int:\n    return 1 if token and strict else 0\n",
    )
    .unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    let opts = AnalyzeOptions {
        base_ref: resolve_base_ref(None, false, &dir),
        head_ref: None,
        config: Config::default(),
    };
    let (findings, blast) = analyze_diff_with_options(&files, &dir, &opts);

    let sig_finding = findings
        .iter()
        .find(|f| f.rule == "breaking/signature-changed")
        .expect("expected breaking/signature-changed finding");
    // Conservative: warning by default (users can promote to blocker via .yupp.toml or --strict)
    assert_eq!(sig_finding.severity, Severity::Warning);
    assert!(sig_finding.message.contains("src/api.py"));

    assert_eq!(blast.len(), 1);
    assert!(blast[0].signature_change.is_some());
    assert_eq!(blast[0].unupdated_callers, vec!["src/api.py"]);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn breaking_signature_change_when_caller_updated_in_pr_is_not_blocker() {
    let dir = make_temp_dir("breaking-updated");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/math.rs"),
        "pub fn scale(x: i32) -> i32 {\n    x * 2\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/app.rs"),
        "pub fn run() -> i32 {\n    scale(5)\n}\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial"]);

    // Update both definition and caller in same PR
    fs::write(
        dir.join("src/math.rs"),
        "pub fn scale(x: i32, factor: i32) -> i32 {\n    x * factor\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/app.rs"),
        "pub fn run() -> i32 {\n    scale(5, 3)\n}\n",
    )
    .unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    let opts = AnalyzeOptions {
        base_ref: Some("HEAD".into()),
        head_ref: None,
        config: Config::default(),
    };
    let (findings, blast) = analyze_diff_with_options(&files, &dir, &opts);

    let sig_finding = findings
        .iter()
        .find(|f| f.rule == "breaking/signature-changed")
        .expect("expected signature-changed warning");
    assert_eq!(sig_finding.severity, Severity::Warning);
    assert!(blast[0].unupdated_callers.is_empty());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn adding_optional_default_param_in_python_is_not_breaking() {
    let dir = make_temp_dir("non-breaking-default");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/client.py"),
        "def fetch(url: str) -> str:\n    return url\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial"]);

    fs::write(
        dir.join("src/client.py"),
        "def fetch(url: str, timeout: int = 30) -> str:\n    return url\n",
    )
    .unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    let opts = AnalyzeOptions {
        base_ref: Some("HEAD".into()),
        head_ref: None,
        config: Config::default(),
    };
    let (findings, _) = analyze_diff_with_options(&files, &dir, &opts);
    assert!(
        !findings.iter().any(|f| f.rule == "breaking/signature-changed"),
        "optional default param should not be flagged as breaking: {:?}",
        findings
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn removed_public_symbol_with_unupdated_caller_is_conservative_warning() {
    let dir = make_temp_dir("removed-public");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/billing.ts"),
        "export function chargeCard(amount: number): boolean {\n  return amount > 0;\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/checkout.ts"),
        "import { chargeCard } from './billing';\nexport function pay() { return chargeCard(10); }\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial"]);

    fs::write(
        dir.join("src/billing.ts"),
        "export function refundCard(amount: number): boolean {\n  return amount > 0;\n}\n",
    )
    .unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    let opts = AnalyzeOptions {
        base_ref: Some("HEAD".into()),
        head_ref: None,
        config: Config::default(),
    };
    let (findings, _) = analyze_diff_with_options(&files, &dir, &opts);

    let removed = findings
        .iter()
        .find(|f| f.rule == "breaking/public-symbol-removed")
        .expect("expected breaking/public-symbol-removed");
    assert_eq!(removed.severity, Severity::Warning);
    assert!(removed.message.contains("src/checkout.ts"));

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// Feature 2: Deep Test-Theater Detector
// =========================================================================

#[test]
fn catches_mock_testing_mock_in_python_and_ts_without_false_positive_on_di() {
    let dir = make_temp_dir("mock-theater");
    fs::create_dir_all(dir.join("tests")).unwrap();

    // 1. Classic Python mock-testing-mock (MUST flag)
    fs::write(
        dir.join("tests/test_fake.py"),
        "\
def test_fetch_user():
    api = MagicMock()
    api.get_user.return_value = {'id': 1}
    res = api.get_user(1)
    assert res == {'id': 1}
    api.get_user.assert_called_once_with(1)
",
    )
    .unwrap();

    // 2. Legitimate Python DI test calling real function (MUST NOT flag)
    fs::write(
        dir.join("tests/test_real_di.py"),
        "\
def test_welcome_email():
    mailer = MagicMock()
    send_welcome_email(mailer, 'a@b.com')
    mailer.send.assert_called_once_with('a@b.com')
",
    )
    .unwrap();

    // 3. Classic TS mock-testing-mock (MUST flag)
    fs::write(
        dir.join("tests/fake.test.ts"),
        "\
test('fetches user from mock', () => {
  const fetchUser = jest.fn().mockReturnValue({ id: 1 });
  const res = fetchUser(1);
  expect(res).toEqual({ id: 1 });
  expect(fetchUser).toHaveBeenCalledWith(1);
});
",
    )
    .unwrap();

    let diff = "\
+++ b/tests/test_fake.py
@@ -1,1 +1,6 @@
+def test_fetch_user():
+    api = MagicMock()
+    api.get_user.return_value = {'id': 1}
+    res = api.get_user(1)
+    assert res == {'id': 1}
+    api.get_user.assert_called_once_with(1)
+++ b/tests/test_real_di.py
@@ -1,1 +1,4 @@
+def test_welcome_email():
+    mailer = MagicMock()
+    send_welcome_email(mailer, 'a@b.com')
+    mailer.send.assert_called_once_with('a@b.com')
+++ b/tests/fake.test.ts
@@ -1,1 +1,6 @@
+test('fetches user from mock', () => {
+  const fetchUser = jest.fn().mockReturnValue({ id: 1 });
+  const res = fetchUser(1);
+  expect(res).toEqual({ id: 1 });
+  expect(fetchUser).toHaveBeenCalledWith(1);
+});
";

    let files = parse_unified_diff(diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    let mock_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "test-theater/mock-testing-mock")
        .collect();
    assert_eq!(mock_findings.len(), 2, "got: {:?}", mock_findings);
    assert!(mock_findings.iter().any(|f| f.file == "tests/test_fake.py"));
    assert!(mock_findings.iter().any(|f| f.file == "tests/fake.test.ts"));
    assert!(!mock_findings.iter().any(|f| f.file == "tests/test_real_di.py"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn flags_untested_new_public_function_and_clears_when_tested() {
    let dir = make_temp_dir("untested-public");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    fs::write(
        dir.join("src/pricing.rs"),
        "pub fn compute_discount(total: i32) -> i32 {\n    total / 10\n}\n\npub fn compute_tax(total: i32) -> i32 {\n    total / 5\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("tests/pricing_test.rs"),
        "#[test]\nfn test_tax() {\n    assert_eq!(compute_tax(100), 20);\n}\n",
    )
    .unwrap();

    let diff = "\
+++ b/src/pricing.rs
@@ -1,1 +1,7 @@
+pub fn compute_discount(total: i32) -> i32 {
+    total / 10
+}
+
+pub fn compute_tax(total: i32) -> i32 {
+    total / 5
+}
";
    let files = parse_unified_diff(diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    let untested: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "test-theater/untested-new-public")
        .collect();
    assert_eq!(untested.len(), 1, "expected only compute_discount: {:?}", untested);
    assert!(untested[0].message.contains("compute_discount"));
    assert!(!untested[0].message.contains("compute_tax"));

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// Feature 3: High-Signal AI Slop Rules
// =========================================================================

#[test]
fn catches_silent_fallback_catches_debug_leftovers_and_duplicate_ast() {
    let dir = make_temp_dir("slop-rules");
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/worker.py"),
        "\
def load_user(uid):
    try:
        return fetch(uid)
    except Exception:
        return None

def process_alpha(items):
    total = 0
    for item in items:
        if item > 0:
            total = total + item * 2
        else:
            total = total - 1
    return total

def process_beta(records):
    acc = 0
    for rec in records:
        if rec > 0:
            acc = acc + rec * 2
        else:
            acc = acc - 1
    return acc
",
    )
    .unwrap();

    fs::write(
        dir.join("src/ui.ts"),
        "\
export function renderWidget(x: number) {
  console.log('debug', x);
  // console.log('commented out should not trigger');
  try {
    return x + 1;
  } catch (e) {
    return null;
  }
}
",
    )
    .unwrap();

    let py_src = fs::read_to_string(dir.join("src/worker.py")).unwrap();
    let ts_src = fs::read_to_string(dir.join("src/ui.ts")).unwrap();
    let mut diff = String::from("+++ b/src/worker.py\n@@ -1,1 +1,24 @@\n");
    for l in py_src.lines() {
        diff.push('+');
        diff.push_str(l);
        diff.push('\n');
    }
    diff.push_str("+++ b/src/ui.ts\n@@ -1,1 +1,9 @@\n");
    for l in ts_src.lines() {
        diff.push('+');
        diff.push_str(l);
        diff.push('\n');
    }

    let files = parse_unified_diff(&diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    let fallbacks: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "slop/silent-fallback-catch")
        .collect();
    assert_eq!(fallbacks.len(), 2, "expected py + ts fallback catches: {:?}", fallbacks);
    assert!(
        !findings.iter().any(|f| f.rule == "slop/empty-catch"),
        "fallback catch should not double-fire as empty-catch"
    );

    let debugs: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "slop/debug-leftover")
        .collect();
    assert_eq!(debugs.len(), 1, "only uncommented console.log should trigger: {:?}", debugs);

    let dups: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "slop/duplicate-code")
        .collect();
    assert_eq!(dups.len(), 1, "expected AST structural duplicate: {:?}", dups);
    assert!(dups[0].message.contains("process_beta"));
    assert!(dups[0].message.contains("process_alpha"));

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// Feature 4: Daily Ergonomics (.yupp.toml, yupp init, --format sarif)
// =========================================================================

#[test]
fn config_parsing_filtering_and_init_with_git_hook() {
    let dir = make_temp_dir("config-init");
    init_git_repo(&dir);

    // 1. yupp init creates .yupp.toml and executable pre-commit hook
    let actions = init_config(&dir, false, Some("pre-commit")).unwrap();
    assert_eq!(actions.len(), 2);
    assert!(dir.join(".yupp.toml").exists());
    assert!(dir.join(".git/hooks/pre-commit").exists());

    // Without --force, second init fails
    assert!(init_config(&dir, false, None).is_err());
    // With --force, succeeds
    assert!(init_config(&dir, true, Some("pre-push")).is_ok());

    // 2. Parse custom .yupp.toml
    let custom_toml = r#"
# Custom config
strict = true
disable = [
  "slop/rust-unwrap",
  "test-theater/untested-new-public",
]
ignore = [
  "migrations/",
  "*.generated.ts",
]

[severity]
"slop/debug-leftover" = "blocker"
"slop/type-suppression" = "off"
"#;
    let cfg = Config::parse_toml(custom_toml).unwrap();
    assert_eq!(cfg.strict, Some(true));
    assert!(cfg.is_ignored("migrations/001_init.py"));
    assert!(cfg.is_ignored("src/api.generated.ts"));
    assert!(!cfg.is_ignored("src/api.ts"));
    assert_eq!(
        cfg.severity.get("slop/debug-leftover"),
        Some(&SeverityOverride::Blocker)
    );
    assert_eq!(
        cfg.severity.get("slop/type-suppression"),
        Some(&SeverityOverride::Off)
    );

    // Verify invalid TOML returns Err
    assert!(Config::parse_toml("strict = maybe").is_err());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sarif_2_1_0_output_is_valid_and_complete() {
    let dir = make_temp_dir("sarif");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("src/leak.rs"),
        "pub fn bad() {\n    dbg!(42);\n    let _ = \"AKIAIOSFODNN7EXAMPLE\";\n}\n",
    )
    .unwrap();

    let diff = "\
+++ b/src/leak.rs
@@ -1,1 +1,4 @@
+pub fn bad() {
+    dbg!(42);
+    let _ = \"AKIAIOSFODNN7EXAMPLE\";
+}
";
    let files = parse_unified_diff(diff);
    let (findings, blast_radius) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());
    let blockers = findings.iter().filter(|f| f.severity == Severity::Blocker).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();

    let verdict = Verdict::from_counts(blockers, warnings, false);
    let report = Report {
        version: env!("CARGO_PKG_VERSION"),
        verdict,
        passed: verdict != Verdict::Nope,
        files_scanned: 1,
        lines_added: 4,
        lines_removed: 0,
        elapsed_ms: 2,
        blockers,
        warnings,
        findings,
        blast_radius,
    };

    let sarif_str = render_sarif(&report);
    let sarif: Value = serde_json::from_str(&sarif_str).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "yupp");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["ruleId"] == "secret/aws" && r["level"] == "error"));
    assert!(results.iter().any(|r| r["ruleId"] == "slop/debug-leftover" && r["level"] == "warning"));

    let term = render_terminal(&report, false);
    assert!(term.contains("nope [FAIL]"));

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// Feature 5: Native MCP Server Mode (yupp mcp) + CLI E2E
// =========================================================================

#[test]
fn mcp_in_process_jsonrpc_protocol_and_tools() {
    let dir = make_temp_dir("mcp-inproc");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("src/svc.py"),
        "def compute_score(x):\n    breakpoint()\n    return x\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/caller.py"),
        "from svc import compute_score\ncompute_score(10)\n",
    )
    .unwrap();

    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "yupp_check_file",
                "arguments": {
                    "repo_path": dir.to_string_lossy(),
                    "file_path": "src/svc.py"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "yupp_blast_radius",
                "arguments": {
                    "repo_path": dir.to_string_lossy(),
                    "symbol": "compute_score",
                    "file": "src/svc.py"
                }
            }
        }),
        json!({"jsonrpc": "2.0", "id": 6, "method": "unknown/method"}),
    ];

    let mut input = String::new();
    for r in &requests {
        input.push_str(&r.to_string());
        input.push('\n');
    }
    input.push_str("{malformed json\n");

    let mut out_buf = Vec::new();
    run_mcp_io(BufReader::new(input.as_bytes()), &mut out_buf).unwrap();
    let out_str = String::from_utf8(out_buf).unwrap();
    let responses: Vec<Value> = out_str
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON-RPC"))
        .collect();

    // 7 requests: notification produces 0 responses, malformed JSON produces 1 error -> 7 responses total
    assert_eq!(responses.len(), 7, "responses: {:?}", responses);

    // 1. initialize
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "yupp");
    // 2. ping
    assert_eq!(responses[1]["id"], 2);
    // 3. tools/list
    let tools = responses[2]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
    // 4. yupp_check_file
    assert_eq!(responses[3]["id"], 4);
    assert_eq!(responses[3]["result"]["isError"], false);
    let check_text = responses[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(check_text.contains("slop/debug-leftover"));
    // 5. yupp_blast_radius
    assert_eq!(responses[4]["id"], 5);
    let blast_text = responses[4]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(blast_text.contains("src/caller.py"));
    // 6. unknown method -> -32601
    assert_eq!(responses[5]["error"]["code"], -32601);
    // 7. malformed JSON -> -32700
    assert_eq!(responses[6]["error"]["code"], -32700);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cli_binary_e2e_init_sarif_and_mcp_subprocess() {
    let dir = make_temp_dir("cli-e2e");
    init_git_repo(&dir);

    // 1. `yupp init --repo <dir> --hook pre-commit`
    let init_out = Command::new(yupp_bin())
        .args(["init", "--repo", &dir.to_string_lossy(), "--hook", "pre-commit"])
        .output()
        .unwrap();
    assert!(init_out.status.success(), "init stderr: {}", String::from_utf8_lossy(&init_out.stderr));
    assert!(dir.join(".yupp.toml").exists());

    // 2. `yupp --stdin --format sarif --no-emoji`
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy(), "--format", "sarif", "--no-emoji"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"+++ b/src/clean.rs\n@@ -1,1 +1,3 @@\n+fn ok() -> i32 { 1 }\n")
        .unwrap();
    let sarif_out = child.wait_with_output().unwrap();
    assert!(sarif_out.status.success());
    let sarif: Value = serde_json::from_slice(&sarif_out.stdout).expect("SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");

    // 3. `yupp mcp` subprocess handshake
    let mut mcp = Command::new(yupp_bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = mcp.stdin.as_mut().unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        )
        .unwrap();
    }
    let mcp_out = mcp.wait_with_output().unwrap();
    assert!(mcp_out.status.success());
    let resp: Value = serde_json::from_slice(&mcp_out.stdout).expect("MCP JSON-RPC");
    assert_eq!(resp["result"]["serverInfo"]["name"], "yupp");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cli_range_diff_config_overrides_and_go_breaking_signature() {
    let dir = make_temp_dir("cli-range-cfg");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("pkg")).unwrap();

    fs::write(
        dir.join("pkg/cfg.go"),
        "package pkg\n\nfunc LoadConfig(path string) error {\n\treturn nil\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("pkg/app.go"),
        "package pkg\n\nfunc Start() error {\n\treturn LoadConfig(\"a.yaml\")\n}\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "v1"]);

    // Break Go exported function signature + add debug leftover
    fs::write(
        dir.join("pkg/cfg.go"),
        "package pkg\n\nimport \"fmt\"\n\nfunc LoadConfig(path string, strict bool) (int, error) {\n\tfmt.Println(path)\n\treturn 0, nil\n}\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "v2 breaking"]);

    // Run `yupp HEAD~1..HEAD --repo <dir>` -> warnings only, so exit 0 with `hmm 🤔`
    let out = Command::new(yupp_bin())
        .args(["HEAD~1..HEAD", "--repo", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hmm 🤔"), "stdout: {}", stdout);
    assert!(stdout.contains("breaking/signature-changed"), "stdout: {}", stdout);
    assert!(stdout.contains("slop/debug-leftover"), "stdout: {}", stdout);

    // With --strict -> exit 1 with `nope ❌`
    let strict_out = Command::new(yupp_bin())
        .args(["HEAD~1..HEAD", "--repo", &dir.to_string_lossy(), "--strict"])
        .output()
        .unwrap();
    assert_eq!(strict_out.status.code(), Some(1));
    let strict_stdout = String::from_utf8_lossy(&strict_out.stdout);
    assert!(strict_stdout.contains("nope ❌"), "strict_stdout: {}", strict_stdout);

    // Promote breaking/signature-changed to blocker via .yupp.toml -> exit 1 with `nope ❌`
    fs::write(
        dir.join(".yupp.toml"),
        "[severity]\n\"breaking/signature-changed\" = \"blocker\"\n",
    )
    .unwrap();
    let promoted = Command::new(yupp_bin())
        .args(["HEAD~1..HEAD", "--repo", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(promoted.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&promoted.stdout).contains("nope ❌"));

    // Now disable breaking/signature-changed and slop/debug-leftover -> exit 0 with `yupp 👌`
    fs::write(
        dir.join(".yupp.toml"),
        "disable = [\"breaking/signature-changed\", \"slop/debug-leftover\"]\n",
    )
    .unwrap();
    let out2 = Command::new(yupp_bin())
        .args(["HEAD~1..HEAD", "--repo", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout2.contains("yupp 👌"), "stdout2: {}", stdout2);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn mcp_scan_diff_tool_on_real_git_repo() {
    let dir = make_temp_dir("mcp-scan-diff");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("src/lib.rs"), "pub fn hi() -> i32 { 1 }\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "init"]);

    // Introduce fake secret pattern in working tree (assembled at runtime)
    let fake_key = format!("sk_{}_{}", "live", "51N9x8K2f9a8b7c6d5e4f3g2h1");
    fs::write(
        dir.join("src/lib.rs"),
        format!(
            "pub fn hi() -> i32 {{\n    let _ = \"{}\";\n    1\n}}\n",
            fake_key
        ),
    )
    .unwrap();

    let req = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "yupp_scan_diff",
            "arguments": {
                "repo_path": dir.to_string_lossy()
            }
        }
    });
    let input = format!("{}\n", req);
    let mut out_buf = Vec::new();
    run_mcp_io(BufReader::new(input.as_bytes()), &mut out_buf).unwrap();
    let resp: Value = serde_json::from_slice(&out_buf).unwrap();
    assert_eq!(resp["id"], 9);
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["verdict"], "nope");
    assert_eq!(parsed["report"]["verdict"], "nope");
    assert!(text.contains("secret/stripe"), "text: {}", text);
    assert!(text.contains("nope ❌"), "text: {}", text);

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// High-Precision Engineering Review Regression Tests
// =========================================================================

#[test]
fn generic_method_names_do_not_emit_noisy_breaking_or_blast_radius_false_positives() {
    let dir = make_temp_dir("generic-names");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/store.py"),
        "class Store:\n    def save(self, data):\n        return data\n    def run(self):\n        return True\n    def get(self, k):\n        return k\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/unrelated.py"),
        "def other(db, cache, job):\n    db.save(1)\n    cache.get('x')\n    job.run()\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "v1"]);

    // Change signatures of generic methods `save`, `run`, `get`
    fs::write(
        dir.join("src/store.py"),
        "class Store:\n    def save(self, data, force):\n        return data\n    def run(self, mode):\n        return mode\n    def get(self, k, default):\n        return default\n",
    )
    .unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    let opts = AnalyzeOptions {
        base_ref: Some("HEAD".into()),
        head_ref: None,
        config: Config::default(),
    };
    let (findings, blast) = analyze_diff_with_options(&files, &dir, &opts);

    assert!(
        !findings.iter().any(|f| f.rule.starts_with("breaking/")),
        "generic method names should not trigger noisy breaking findings: {:?}",
        findings
    );
    assert!(
        blast.is_empty(),
        "generic method names should not pollute blast radius: {:?}",
        blast
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn diff_aware_mock_testing_mock_catches_sut_mocks_without_flagging_di_dependencies() {
    let dir = make_temp_dir("diff-aware-mock");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    // Production files modified in this PR
    fs::write(
        dir.join("src/auth.py"),
        "def verify_token(token: str) -> bool:\n    return len(token) > 5\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/email.py"),
        "def send_welcome_email(user: str) -> bool:\n    return smtp_client.send(user)\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/billing.ts"),
        "export function chargeCard(amount: number): boolean {\n  return amount > 0;\n}\n",
    )
    .unwrap();

    // 1. BAD Python: @patch mocks the EXACT diff-modified function `verify_token` and only asserts mock call
    fs::write(
        dir.join("tests/test_bad_patch.py"),
        "\
@patch('src.auth.verify_token')
def test_verify_token(mock_verify):
    mock_verify.return_value = True
    res = verify_token('abc')
    mock_verify.assert_called_once_with('abc')
    assert res is True
",
    )
    .unwrap();

    // 2. GOOD Python: @patch mocks a DEPENDENCY (`smtp_client`), NOT `send_welcome_email`
    fs::write(
        dir.join("tests/test_good_dep_patch.py"),
        "\
@patch('src.email.smtp_client')
def test_send_welcome_email(mock_smtp):
    send_welcome_email('a@b.com')
    mock_smtp.send.assert_called_once_with('a@b.com')
",
    )
    .unwrap();

    // 3. BAD TS: jest.mock mocks the diff-modified module `../src/billing` and only asserts toHaveBeenCalled
    fs::write(
        dir.join("tests/bad_billing.test.ts"),
        "\
jest.mock('../src/billing');
test('chargeCard works', () => {
  chargeCard(100);
  expect(chargeCard).toHaveBeenCalledWith(100);
});
",
    )
    .unwrap();

    // 4. GOOD TS: legitimate DI test mocking logger dependency while calling real function
    fs::write(
        dir.join("tests/good_di.test.ts"),
        "\
test('logs when processing order', () => {
  const logger = { info: jest.fn() };
  processOrder(logger, 42);
  expect(logger.info).toHaveBeenCalled();
});
",
    )
    .unwrap();

    let diff = "\
+++ b/src/auth.py
@@ -1,1 +1,2 @@
+def verify_token(token: str) -> bool:
+    return len(token) > 5
+++ b/src/email.py
@@ -1,1 +1,2 @@
+def send_welcome_email(user: str) -> bool:
+    return smtp_client.send(user)
+++ b/src/billing.ts
@@ -1,1 +1,3 @@
+export function chargeCard(amount: number): boolean {
+  return amount > 0;
+}
+++ b/tests/test_bad_patch.py
@@ -1,1 +1,6 @@
+@patch('src.auth.verify_token')
+def test_verify_token(mock_verify):
+    mock_verify.return_value = True
+    res = verify_token('abc')
+    mock_verify.assert_called_once_with('abc')
+    assert res is True
+++ b/tests/test_good_dep_patch.py
@@ -1,1 +1,4 @@
+@patch('src.email.smtp_client')
+def test_send_welcome_email(mock_smtp):
+    send_welcome_email('a@b.com')
+    mock_smtp.send.assert_called_once_with('a@b.com')
+++ b/tests/bad_billing.test.ts
@@ -1,1 +1,5 @@
+jest.mock('../src/billing');
+test('chargeCard works', () => {
+  chargeCard(100);
+  expect(chargeCard).toHaveBeenCalledWith(100);
+});
+++ b/tests/good_di.test.ts
@@ -1,1 +1,5 @@
+test('logs when processing order', () => {
+  const logger = { info: jest.fn() };
+  processOrder(logger, 42);
+  expect(logger.info).toHaveBeenCalled();
+});
";

    let files = parse_unified_diff(diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    let mock_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule == "test-theater/mock-testing-mock")
        .collect();
    assert_eq!(mock_findings.len(), 2, "got: {:?}", mock_findings);
    assert!(mock_findings.iter().any(|f| f.file == "tests/test_bad_patch.py"));
    assert!(mock_findings.iter().any(|f| f.file == "tests/bad_billing.test.ts"));
    assert!(!mock_findings.iter().any(|f| f.file == "tests/test_good_dep_patch.py"));
    assert!(!mock_findings.iter().any(|f| f.file == "tests/good_di.test.ts"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn catches_placeholder_stubs_and_ignores_string_literal_false_positives() {
    let dir = make_temp_dir("stubs-and-strings");
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/stubs.py"),
        "\
def compute_tax(amount):
    pass

@abstractmethod
def abstract_hook(self):
    pass
",
    )
    .unwrap();

    fs::write(
        dir.join("src/stubs.ts"),
        "\
export function computeFee(x: number) {
  // implement logic here
}
",
    )
    .unwrap();

    fs::write(
        dir.join("src/messages.rs"),
        "\
pub fn describe_rules() -> &'static str {
    let _a = \"todo!() and unimplemented!() and .unwrap()\";
    let _b = \"@ts-ignore and console.log(1)\";
    \"ok\"
}
",
    )
    .unwrap();

    let diff = "\
+++ b/src/stubs.py
@@ -1,1 +1,6 @@
+def compute_tax(amount):
+    pass
+
+@abstractmethod
+def abstract_hook(self):
+    pass
+++ b/src/stubs.ts
@@ -1,1 +1,3 @@
+export function computeFee(x: number) {
+  // implement logic here
+}
+++ b/src/messages.rs
@@ -1,1 +1,5 @@
+pub fn describe_rules() -> &'static str {
+    let _a = \"todo!() and unimplemented!() and .unwrap()\";
+    let _b = \"@ts-ignore and console.log(1)\";
+    \"ok\"
+}
";

    let files = parse_unified_diff(diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    // Python `compute_tax` stub flagged, `@abstractmethod` NOT flagged
    let py_stubs: Vec<_> = findings
        .iter()
        .filter(|f| f.file == "src/stubs.py" && f.rule == "slop/unfinished-stub")
        .collect();
    assert_eq!(py_stubs.len(), 1, "expected only compute_tax: {:?}", py_stubs);

    // TS `computeFee` placeholder flagged
    assert!(findings
        .iter()
        .any(|f| f.file == "src/stubs.ts" && f.rule == "slop/unfinished-stub"));

    // Rust string literals MUST NOT trigger slop/unfinished-stub, slop/rust-unwrap, slop/type-suppression, or slop/debug-leftover
    let rs_slop: Vec<_> = findings
        .iter()
        .filter(|f| f.file == "src/messages.rs" && f.rule.starts_with("slop/"))
        .collect();
    assert!(rs_slop.is_empty(), "string literals must not false-positive: {:?}", rs_slop);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cli_three_state_verdicts_json_pr_comment_and_exit_codes() {
    let dir = make_temp_dir("three-state-cli");
    fs::create_dir_all(dir.join("src")).unwrap();

    // 1. Clean diff -> yupp 👌 / yupp [OK] / JSON "yupp" / exit 0
    let mut c1 = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy(), "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c1.stdin
        .as_mut()
        .unwrap()
        .write_all(b"+++ b/src/clean.rs\n@@ -1,1 +1,1 @@\n+fn ok() -> i32 { 1 }\n")
        .unwrap();
    let o1 = c1.wait_with_output().unwrap();
    assert_eq!(o1.status.code(), Some(0));
    let j1: Value = serde_json::from_slice(&o1.stdout).unwrap();
    assert_eq!(j1["verdict"], "yupp");

    // 2. Warning-only diff -> hmm 🤔 / hmm [WARN] / JSON "hmm" / exit 0
    let warn_diff = b"+++ b/src/w.rs\n@@ -1,1 +1,1 @@\n+fn f() { todo!(); }\n";
    let mut c2 = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c2.stdin.as_mut().unwrap().write_all(warn_diff).unwrap();
    let o2 = c2.wait_with_output().unwrap();
    assert_eq!(o2.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o2.stdout).contains("hmm 🤔"));

    let mut c2_ascii = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy(), "--no-emoji", "--format", "pr-comment"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c2_ascii.stdin.as_mut().unwrap().write_all(warn_diff).unwrap();
    let o2_ascii = c2_ascii.wait_with_output().unwrap();
    assert_eq!(o2_ascii.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o2_ascii.stdout).contains("### hmm [WARN]"));

    let mut c2_json = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy(), "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c2_json.stdin.as_mut().unwrap().write_all(warn_diff).unwrap();
    let o2_json = c2_json.wait_with_output().unwrap();
    assert_eq!(o2_json.status.code(), Some(0));
    let j2: Value = serde_json::from_slice(&o2_json.stdout).unwrap();
    assert_eq!(j2["verdict"], "hmm");

    // 3. Warning-only diff with --strict -> nope ❌ / exit 1 / JSON "nope"
    let mut c3 = Command::new(yupp_bin())
        .args(["--stdin", "--repo", &dir.to_string_lossy(), "--strict"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c3.stdin.as_mut().unwrap().write_all(warn_diff).unwrap();
    let o3 = c3.wait_with_output().unwrap();
    assert_eq!(o3.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o3.stdout).contains("nope ❌"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn comprehensive_test_theater_across_python_ts_rust_go() {
    let dir = make_temp_dir("theater-all-langs");
    fs::create_dir_all(dir.join("tests")).unwrap();

    fs::write(
        dir.join("tests/test_py.py"),
        "@pytest.mark.skip\ndef test_skipped():\n    assert 1 == 1\n",
    )
    .unwrap();
    fs::write(
        dir.join("tests/empty_test.go"),
        "package tests\n\nimport \"testing\"\n\nfunc TestEmpty(t *testing.T) {\n\tx := 1\n\t_ = x\n}\n\nfunc TestSkipped(t *testing.T) {\n\tt.Skip(\"later\")\n}\n",
    )
    .unwrap();
    fs::write(
        dir.join("tests/rust_test.rs"),
        "#[test]\n#[ignore]\nfn ignored_case() {\n    assert_eq!(1, 1);\n}\n",
    )
    .unwrap();

    let diff = "\
+++ b/tests/test_py.py
@@ -1,1 +1,3 @@
+@pytest.mark.skip
+def test_skipped():
+    assert 1 == 1
+++ b/tests/empty_test.go
@@ -1,1 +1,11 @@
+package tests
+
+import \"testing\"
+
+func TestEmpty(t *testing.T) {
+	x := 1
+	_ = x
+}
+
+func TestSkipped(t *testing.T) {
+	t.Skip(\"later\")
+}
+++ b/tests/rust_test.rs
@@ -1,1 +1,5 @@
+#[test]
+#[ignore]
+fn ignored_case() {
+    assert_eq!(1, 1);
+}
";

    let files = parse_unified_diff(diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    assert!(findings.iter().any(|f| f.file == "tests/test_py.py" && f.rule == "test-theater/skipped-test"));
    assert!(findings.iter().any(|f| f.file == "tests/test_py.py" && f.rule == "test-theater/trivial-assertion"));
    assert!(findings.iter().any(|f| f.file == "tests/empty_test.go" && f.rule == "test-theater/empty-test"));
    assert!(findings.iter().any(|f| f.file == "tests/empty_test.go" && f.rule == "test-theater/skipped-test"));
    assert!(findings.iter().any(|f| f.file == "tests/rust_test.rs" && f.rule == "test-theater/skipped-test"));
    assert!(findings.iter().any(|f| f.file == "tests/rust_test.rs" && f.rule == "test-theater/trivial-assertion"));

    let _ = fs::remove_dir_all(dir);
}

// =========================================================================
// Polish & Edge Cases: ANSI Colors, Whole-File Deletions, Multiline Strings
// =========================================================================

#[test]
fn cli_ansi_color_flags_and_tty_auto_disable() {
    let dir = make_temp_dir("cli-color");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("src/parse.rs"),
        "pub fn parse_num(s: &str) -> i32 {\n    s.parse().unwrap()\n}\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(
        dir.join("tests/parse_test.rs"),
        "#[test]\nfn test_parse_num() { assert_eq!(parse_num(\"1\"), 1); }\n",
    )
    .unwrap();

    let warn_diff = "\
+++ b/src/parse.rs
@@ -1,1 +1,3 @@
+pub fn parse_num(s: &str) -> i32 {
+    s.parse().unwrap()
+}
";

    // 1. Piped stdout (non-TTY) with default --color auto => NO ANSI codes
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--repo"])
        .arg(&dir)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(warn_diff.as_bytes())
        .unwrap();
    let out_auto = child.wait_with_output().unwrap();
    assert!(out_auto.status.success());
    let auto_str = String::from_utf8_lossy(&out_auto.stdout);
    assert!(!auto_str.contains("\x1b["), "expected no ANSI in piped auto mode: {}", auto_str);
    assert!(auto_str.contains("hmm 🤔"));

    // 2. --color always => ANSI yellow verdict + bold file:line + dimmed rule
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--color", "always", "--repo"])
        .arg(&dir)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(warn_diff.as_bytes())
        .unwrap();
    let out_always = child.wait_with_output().unwrap();
    assert!(out_always.status.success());
    let always_str = String::from_utf8_lossy(&out_always.stdout);
    assert!(always_str.contains("\x1b[1;33mhmm 🤔\x1b[0m"), "got: {}", always_str);
    assert!(always_str.contains("\x1b[1msrc/parse.rs:2\x1b[0m"), "got: {}", always_str);
    assert!(always_str.contains("\x1b[2m[slop/rust-unwrap]\x1b[0m"), "got: {}", always_str);

    // 3. --color always --no-color => NO ANSI codes
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--color", "always", "--no-color", "--repo"])
        .arg(&dir)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(warn_diff.as_bytes())
        .unwrap();
    let out_no_color = child.wait_with_output().unwrap();
    let no_color_str = String::from_utf8_lossy(&out_no_color.stdout);
    assert!(!no_color_str.contains("\x1b["), "expected no ANSI with --no-color: {}", no_color_str);

    // 4. --color never => NO ANSI codes
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--color", "never", "--repo"])
        .arg(&dir)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(warn_diff.as_bytes())
        .unwrap();
    let out_never = child.wait_with_output().unwrap();
    let never_str = String::from_utf8_lossy(&out_never.stdout);
    assert!(!never_str.contains("\x1b["), "expected no ANSI with --color never: {}", never_str);

    // 5. NO_COLOR=1 with default --color auto => NO ANSI codes + ASCII verdict
    let mut child = Command::new(yupp_bin())
        .args(["--stdin", "--repo"])
        .arg(&dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(warn_diff.as_bytes())
        .unwrap();
    let out_env = child.wait_with_output().unwrap();
    let env_str = String::from_utf8_lossy(&out_env.stdout);
    assert!(!env_str.contains("\x1b["), "expected no ANSI with NO_COLOR=1: {}", env_str);
    assert!(env_str.contains("hmm [WARN]"), "got: {}", env_str);

    // 6. Direct library check for green yupp / red nope styling via render_terminal_with_color
    let clean_report = Report {
        version: "0.1.0",
        verdict: Verdict::Yupp,
        passed: true,
        files_scanned: 1,
        lines_added: 1,
        lines_removed: 0,
        elapsed_ms: 1,
        blockers: 0,
        warnings: 0,
        findings: vec![],
        blast_radius: vec![],
    };
    assert!(render_terminal_with_color(&clean_report, true, true).contains("\x1b[1;32myupp 👌\x1b[0m"));
    assert!(!render_terminal_with_color(&clean_report, true, false).contains("\x1b["));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn deleted_file_with_public_symbols_surfaces_breaking_symbol_removed_and_callers() {
    let dir = make_temp_dir("whole-file-delete");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();

    fs::write(
        dir.join("src/legacy_billing.py"),
        "def compute_loyalty_discount(amount: float) -> float:\n    return amount * 0.9\n\ndef _internal_helper():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/checkout.py"),
        "from src.legacy_billing import compute_loyalty_discount\n\ndef finalize_order(total):\n    return compute_loyalty_discount(total)\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial billing"]);

    // Delete the entire file in working tree without updating src/checkout.py
    fs::remove_file(dir.join("src/legacy_billing.py")).unwrap();

    let raw_diff = git(&dir, &["diff", "--unified=3"]);
    let files = parse_unified_diff(&raw_diff);
    assert_eq!(files.len(), 1, "expected deleted file to be parsed from diff");
    assert_eq!(files[0].path, "src/legacy_billing.py");
    assert!(files[0].is_deleted);
    assert!(files[0].added.is_empty());
    assert!(!files[0].removed.is_empty());

    // 1. With git base_ref resolved
    let base_ref = resolve_base_ref(None, false, &dir);
    let opts = AnalyzeOptions {
        base_ref,
        head_ref: None,
        config: Config::default(),
    };
    let (findings, blast) = analyze_diff_with_options(&files, &dir, &opts);

    let removed_finding = findings
        .iter()
        .find(|f| f.rule == "breaking/public-symbol-removed")
        .expect("expected breaking/public-symbol-removed for deleted file");
    assert_eq!(removed_finding.severity, Severity::Warning);
    assert_eq!(removed_finding.file, "src/legacy_billing.py");
    assert!(
        removed_finding.message.contains("compute_loyalty_discount"),
        "got: {}",
        removed_finding.message
    );
    assert!(
        removed_finding.message.contains("src/checkout.py"),
        "expected unupdated caller src/checkout.py in message, got: {}",
        removed_finding.message
    );
    assert!(
        !findings.iter().any(|f| f.message.contains("_internal_helper")),
        "private symbol should not emit breaking/public-symbol-removed"
    );
    assert!(
        blast
            .iter()
            .any(|b| b.symbol == "compute_loyalty_discount"
                && b.unupdated_callers.contains(&"src/checkout.py".to_string())),
        "expected blast radius with unupdated caller, got: {:?}",
        blast
    );

    // 2. Also verify fallback when base_ref is None (e.g. piped --stdin without git range)
    let (stdin_findings, _) =
        analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());
    assert!(
        stdin_findings
            .iter()
            .any(|f| f.rule == "breaking/public-symbol-removed"
                && f.message.contains("compute_loyalty_discount")
                && f.message.contains("src/checkout.py")),
        "expected deleted-file fallback to catch removed public symbol without base_ref: {:?}",
        stdin_findings
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn multiline_string_literals_do_not_trigger_slop_false_positives_across_languages() {
    let dir = make_temp_dir("multiline-strings");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    let fake_stripe = format!("sk_{}_{}", "live", "99A8b7C6d5E4f3G2h1J0k9L8");

    // Python: triple-double & triple-single docstrings with slop-like text,
    // plus a real secret inside a multiline string (which MUST still be caught).
    let py_src = format!(
        r#"def render_docs():
    doc = """
    Example snippets:
    todo!()
    console.log("hello")
    breakpoint()
    # TODO: implement this
    # type: ignore
    """
    alt = '''
    NotImplementedError
    pdb.set_trace()
    '''
    leaked = """
    token = {}
    """
    return doc + alt + leaked
"#,
        fake_stripe
    );

    // Rust: multiline raw string r#"..."# with slop-like text,
    // plus a real `.unwrap()` AFTER the closing `"#` on the closing line (MUST be caught).
    let rs_src = r##"pub fn build_prompt() -> usize {
    let template = r#"
    fn fake() {
        let v = x.unwrap();
        todo!();
        unimplemented!();
        dbg!(v);
        // TODO: implement logic
        #[allow(warnings)]
    }
    "#;
    let parsed: usize = r#"
    todo!()
    "#.trim().len().checked_add(1).unwrap();
    template.len() + parsed
}
"##;

    // TypeScript: multiline template literal with slop-like text on interior lines,
    // plus a real `console.log` inside `${...}` interpolation (MUST be caught).
    let ts_src = r#"export function buildTemplate(name: string): string {
  const msg = `
    console.log("just documentation text");
    debugger;
    // @ts-ignore
    // TODO: implement here
    ${console.log("real debug in interpolation")}
  `;
  return msg + name;
}
"#;

    // Go: multiline backtick raw string with fmt.Println & placeholder comment
    let go_src = r#"package docs

func RenderGoHelp() string {
	return `
	fmt.Println("example output")
	// TODO: implement this
	`
}
"#;

    fs::write(dir.join("src/docs.py"), &py_src).unwrap();
    fs::write(dir.join("src/prompt.rs"), rs_src).unwrap();
    fs::write(dir.join("src/tmpl.ts"), ts_src).unwrap();
    fs::write(dir.join("src/help.go"), go_src).unwrap();
    // Add test references so untested-new-public does not clutter findings
    fs::write(
        dir.join("tests/test_all.py"),
        "def test_refs():\n    assert render_docs and build_prompt and buildTemplate and RenderGoHelp\n",
    )
    .unwrap();

    fn make_added_diff(path: &str, src: &str) -> String {
        let lines: Vec<&str> = src.lines().collect();
        let mut s = format!("+++ b/{}\n@@ -0,0 +1,{} @@\n", path, lines.len());
        for l in lines {
            s.push('+');
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    let raw_diff = format!(
        "{}{}{}{}",
        make_added_diff("src/docs.py", &py_src),
        make_added_diff("src/prompt.rs", rs_src),
        make_added_diff("src/tmpl.ts", ts_src),
        make_added_diff("src/help.go", go_src),
    );

    let files = parse_unified_diff(&raw_diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    // Python: zero slop findings, but secret inside multiline string IS caught
    assert!(
        !findings
            .iter()
            .any(|f| f.file == "src/docs.py" && f.rule.starts_with("slop/")),
        "unexpected slop false positives in Python multiline strings: {:?}",
        findings
    );
    assert!(
        findings
            .iter()
            .any(|f| f.file == "src/docs.py" && f.rule == "secret/stripe"),
        "secret inside Python multiline string must still be caught: {:?}",
        findings
    );

    // Rust: no false positive for todo!/dbg!/allow/unwrap inside r#"..."#,
    // ONLY the real `.unwrap()` after closing `"#` on line 14 is flagged.
    let rs_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.file == "src/prompt.rs")
        .collect();
    assert_eq!(
        rs_findings.len(),
        1,
        "expected exactly 1 finding (the real .unwrap() after closing \"#), got: {:?}",
        rs_findings
    );
    assert_eq!(rs_findings[0].rule, "slop/rust-unwrap");
    assert_eq!(rs_findings[0].line, 14);

    // TypeScript: no false positives for interior template literal lines,
    // ONLY the real console.log inside `${...}` on line 7 is flagged.
    let ts_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.file == "src/tmpl.ts")
        .collect();
    assert_eq!(
        ts_findings.len(),
        1,
        "expected exactly 1 finding (real console.log inside template interpolation), got: {:?}",
        ts_findings
    );
    assert_eq!(ts_findings[0].rule, "slop/debug-leftover");
    assert_eq!(ts_findings[0].line, 7);

    // Go: zero slop findings for interior lines of backtick raw string
    assert!(
        !findings
            .iter()
            .any(|f| f.file == "src/help.go" && f.rule.starts_with("slop/")),
        "unexpected slop false positives in Go raw string: {:?}",
        findings
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn parse_unified_diff_preserves_hunk_lines_matching_diff_headers() {
    let raw_diff = "\
diff --git a/src/fixture.rs b/src/fixture.rs
index 1111111..2222222 100644
--- a/src/fixture.rs
+++ b/src/fixture.rs
@@ -1,3 +1,6 @@
 pub fn sample() -> &'static str {
-    \"-- a/old.rs\"
+-- a/removed_header.rs
+++ b/fake_header.rs
+++ /dev/null
+    \"ok\"
 }
";
    let files = parse_unified_diff(raw_diff);
    assert_eq!(files.len(), 1, "hunk lines starting with +++/--- must not split files: {:?}", files);
    assert_eq!(files[0].path, "src/fixture.rs");
    assert!(!files[0].is_deleted);
    assert_eq!(files[0].added.len(), 4);
    assert_eq!(files[0].removed.len(), 1);
    assert_eq!(files[0].added[1].content, "++ b/fake_header.rs");
    assert_eq!(files[0].added[2].content, "++ /dev/null");
}

#[test]
fn multiline_strings_masked_in_historical_commit_range_and_staged_diff() {
    assert_eq!(resolve_head_ref(None, false), None);
    assert_eq!(resolve_head_ref(None, true), Some(String::new()));
    assert_eq!(resolve_head_ref(Some("HEAD~2..HEAD~1"), false), Some("HEAD~1".into()));
    assert_eq!(resolve_head_ref(Some("main...feature"), false), Some("feature".into()));
    assert_eq!(resolve_head_ref(Some("HEAD~1"), false), None);

    let dir = make_temp_dir("multiline-range-staged");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    fs::write(dir.join("src/doc.py"), "def render_help():\n    return ''\n").unwrap();
    fs::write(
        dir.join("tests/test_doc.py"),
        "def test_render_help():\n    assert render_help() is not None\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "initial"]);

    // Commit 1: add multiline docstring containing slop-like text
    fs::write(
        dir.join("src/doc.py"),
        "def render_help():\n    return \"\"\"\n    todo!()\n    breakpoint()\n    # TODO: implement this\n    \"\"\"\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "add docstring"]);

    // Commit 2: shift all lines down by 3 in working tree / HEAD
    fs::write(
        dir.join("src/doc.py"),
        "# line 1\n# line 2\n# line 3\ndef render_help():\n    return \"\"\"\n    todo!()\n    breakpoint()\n    # TODO: implement this\n    \"\"\"\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "shift lines"]);

    // 1. Scanning historical range HEAD~2..HEAD~1 must read HEAD~1 (not HEAD on disk)
    let out_range = Command::new(yupp_bin())
        .args(["HEAD~2..HEAD~1", "--repo", &dir.to_string_lossy(), "--format", "json"])
        .output()
        .unwrap();
    assert!(out_range.status.success(), "stderr: {}", String::from_utf8_lossy(&out_range.stderr));
    let j_range: Value = serde_json::from_slice(&out_range.stdout).unwrap();
    let range_slop: Vec<&Value> = j_range["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"].as_str().unwrap_or("").starts_with("slop/"))
        .collect();
    assert!(
        range_slop.is_empty(),
        "expected 0 slop findings in historical range HEAD~2..HEAD~1, got: {:?}",
        range_slop
    );

    // 2. Stage a multiline string change, then shift lines in the unstaged working tree
    fs::write(
        dir.join("src/doc.py"),
        "# line 1\n# line 2\n# line 3\ndef render_help():\n    return \"\"\"\n    todo!()\n    breakpoint()\n    console.log(\"staged\")\n    \"\"\"\n",
    )
    .unwrap();
    git(&dir, &["add", "src/doc.py"]);
    // Modify working tree without staging so working-tree line numbers diverge from index
    fs::write(
        dir.join("src/doc.py"),
        "# extra 1\n# extra 2\n# line 1\n# line 2\n# line 3\ndef render_help():\n    return \"\"\"\n    todo!()\n    breakpoint()\n    console.log(\"staged\")\n    \"\"\"\n",
    )
    .unwrap();

    let out_staged = Command::new(yupp_bin())
        .args(["--staged", "--repo", &dir.to_string_lossy(), "--format", "json"])
        .output()
        .unwrap();
    assert!(out_staged.status.success(), "stderr: {}", String::from_utf8_lossy(&out_staged.stderr));
    let j_staged: Value = serde_json::from_slice(&out_staged.stdout).unwrap();
    let staged_slop: Vec<&Value> = j_staged["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"].as_str().unwrap_or("").starts_with("slop/"))
        .collect();
    assert!(
        staged_slop.is_empty(),
        "expected 0 slop findings in --staged diff with shifted working tree, got: {:?}",
        staged_slop
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rust_inline_cfg_test_module_skips_prod_slop_catches_empty_test_and_counts_coverage() {
    let dir = make_temp_dir("rust-cfg-test");
    fs::create_dir_all(dir.join("src")).unwrap();

    let rs_src = "\
pub fn parse_header(raw: &str) -> Option<&str> {
    raw.split(':').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> String {
        Some(\"ok\").unwrap().to_string()
    }

    #[test]
    fn parses_valid_header() {
        let h = parse_header(\"a:b\").unwrap();
        assert_eq!(h, \"a\");
    }

    #[test]
    fn empty_inline_test() {
        let _ = helper();
    }
}
";
    fs::write(dir.join("src/header.rs"), rs_src).unwrap();

    let mut diff = String::from("+++ b/src/header.rs\n@@ -0,0 +1,24 @@\n");
    for line in rs_src.lines() {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }

    let files = parse_unified_diff(&diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    assert!(
        !findings.iter().any(|f| f.rule == "slop/rust-unwrap"),
        "inline #[cfg(test)] .unwrap() should not trigger slop/rust-unwrap: {:?}",
        findings
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.rule == "test-theater/untested-new-public"),
        "pub fn tested inside inline #[cfg(test)] should count as tested: {:?}",
        findings
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule == "test-theater/empty-test" && f.message.contains("empty_inline_test")),
        "empty #[test] inside inline #[cfg(test)] must still be caught: {:?}",
        findings
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inline_trailing_comment_does_not_trigger_todo_or_unwrap_slop() {
    let dir = make_temp_dir("inline-trailing-comment");
    fs::create_dir_all(dir.join("src")).unwrap();

    let rs_src = "\
pub fn classify(x: bool) -> bool {
    let ok = x; // Rust `todo!()` / `unimplemented!()` and `.unwrap()` handled elsewhere
    // TODO: implement logic here
    ok
}
";
    fs::write(dir.join("src/classify.rs"), rs_src).unwrap();

    let mut diff = String::from("+++ b/src/classify.rs\n@@ -0,0 +1,5 @@\n");
    for line in rs_src.lines() {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }

    let files = parse_unified_diff(&diff);
    let (findings, _) = analyze_diff_with_options(&files, &dir, &AnalyzeOptions::default());

    assert!(
        !findings.iter().any(|f| f.rule == "slop/rust-unwrap"),
        "inline comment mentioning .unwrap() should not trigger slop/rust-unwrap: {:?}",
        findings
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.rule == "slop/unfinished-stub" && f.line == 2),
        "inline explanatory comment mentioning todo!() should not trigger slop/unfinished-stub: {:?}",
        findings
    );
    assert!(
        findings
            .iter()
            .any(|f| f.rule == "slop/unfinished-stub" && f.line == 3),
        "real placeholder comment on line 3 must still trigger slop/unfinished-stub: {:?}",
        findings
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn repo_scan_skips_build_out_minified_and_config_ignored_paths() {
    let dir = make_temp_dir("skip-build-out");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::create_dir_all(dir.join("out/_next/static/chunks")).unwrap();
    fs::create_dir_all(dir.join("generated")).unwrap();

    fs::write(
        dir.join("src/redact.js"),
        "export function redactTokens(s) { return s; }\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/app.js"),
        "import { redactTokens } from './redact';\nexport const v = redactTokens('x');\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/bundle.min.js"),
        "redactTokens('minified');\n",
    )
    .unwrap();
    fs::write(
        dir.join("out/_next/static/chunks/218.js"),
        "redactTokens('build-output');\n",
    )
    .unwrap();
    fs::write(
        dir.join("generated/client.js"),
        "redactTokens('generated');\n",
    )
    .unwrap();

    let diff = "+++ b/src/redact.js\n@@ -0,0 +1,1 @@\n+export function redactTokens(s) { return s; }\n";
    let files = parse_unified_diff(diff);
    let opts = AnalyzeOptions {
        base_ref: None,
        head_ref: None,
        config: Config::parse_toml("ignore = [\"generated/**\"]\n").unwrap(),
    };
    let (_, blast) = analyze_diff_with_options(&files, &dir, &opts);

    let entry = blast
        .iter()
        .find(|b| b.symbol == "redactTokens")
        .expect("expected blast radius for redactTokens");
    let caller_files: Vec<&str> = entry.callers.iter().map(|c| c.file.as_str()).collect();
    assert_eq!(caller_files, vec!["src/app.js"]);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn git_show_files_batch_fetches_multiple_revisions_and_ignores_missing_blobs() {
    use yupp::diff::git_show_files_batch;

    let dir = make_temp_dir("git-batch-fetch");
    init_git_repo(&dir);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("src/a.rs"), "pub fn v1() -> i32 { 1 }\n").unwrap();
    fs::write(dir.join("src/b.rs"), "pub fn b1() -> i32 { 2 }\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "c1"]);

    fs::write(dir.join("src/a.rs"), "pub fn v2() -> i32 { 10 }\n").unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "c2"]);

    let specs = vec![
        ("HEAD~1".to_string(), "src/a.rs".to_string()),
        ("HEAD".to_string(), "src/a.rs".to_string()),
        ("HEAD".to_string(), "src/b.rs".to_string()),
        ("HEAD".to_string(), "src/does_not_exist.rs".to_string()),
    ];
    let map = git_show_files_batch(&dir, &specs);
    assert_eq!(
        map.get(&("HEAD~1".to_string(), "src/a.rs".to_string())).map(|s| s.as_str()),
        Some("pub fn v1() -> i32 { 1 }\n")
    );
    assert_eq!(
        map.get(&("HEAD".to_string(), "src/a.rs".to_string())).map(|s| s.as_str()),
        Some("pub fn v2() -> i32 { 10 }\n")
    );
    assert_eq!(
        map.get(&("HEAD".to_string(), "src/b.rs".to_string())).map(|s| s.as_str()),
        Some("pub fn b1() -> i32 { 2 }\n")
    );
    assert!(!map.contains_key(&("HEAD".to_string(), "src/does_not_exist.rs".to_string())));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cli_outside_git_repo_prints_clean_hint_instead_of_git_usage_spam() {
    let dir = make_temp_dir("non-git-dir");
    let out = Command::new(yupp_bin())
        .args(["--repo", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a git repository"),
        "expected clean non-git error, got: {}",
        stderr
    );
    assert!(
        stderr.contains("hint: run `yupp` inside a git repo"),
        "expected helpful hint, got: {}",
        stderr
    );
    assert!(
        !stderr.contains("Diff output format options"),
        "must not dump raw git diff usage spam: {}",
        stderr
    );

    let _ = fs::remove_dir_all(dir);
}
