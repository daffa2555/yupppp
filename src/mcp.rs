use crate::ast::{analyze_diff_with_options, compute_symbol_blast_radius, AnalyzeOptions, Severity};
use crate::config::Config;
use crate::diff::{parse_unified_diff, resolve_base_ref, DiffLine, FileDiff};
use crate::report::{render_terminal, Report, Verdict};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub fn run_mcp_stdio() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    run_mcp_io(reader, &mut writer)
}

pub fn run_mcp_io<R: BufRead, W: Write>(reader: R, writer: &mut W) -> io::Result<()> {
    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
                writeln!(writer, "{}", err)?;
                writer.flush()?;
                continue;
            }
        };

        if let Some(resp) = handle_jsonrpc_message(&req) {
            writeln!(writer, "{}", resp)?;
            writer.flush()?;
        }
    }
    Ok(())
}

pub fn handle_jsonrpc_message(req: &Value) -> Option<Value> {
    if !req.is_object() {
        return Some(jsonrpc_error(Value::Null, -32600, "Invalid Request: expected JSON object"));
    }
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = req.get("id").cloned();

    // JSON-RPC notifications (no `id`) must not receive a response.
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap();

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "yupp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })),
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": tool_definitions()
            }
        })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
                return Some(jsonrpc_error(id, -32602, "Missing tool `name` in params"));
            };
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let tool_result = dispatch_tool(name, &args);
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": tool_result
            }))
        }
        _ => Some(jsonrpc_error(
            id,
            -32601,
            &format!("Method not found: {}", method),
        )),
    }
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "yupp_scan_diff",
            "description": "Run 0-LLM Tree-sitter AST PR verification on a git diff range, staged changes, working tree, or raw unified diff. Catches breaking public signature changes, test theater (removed assertions, empty tests, mock-testing-mock, untested new public APIs), silent slop, debug leftovers, duplicate AST code, and leaked secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to current working directory)"
                    },
                    "range": {
                        "type": "string",
                        "description": "Git diff range, e.g. 'main..HEAD' or 'HEAD~1'"
                    },
                    "staged": {
                        "type": "boolean",
                        "description": "Inspect staged changes (git diff --cached)"
                    },
                    "diff": {
                        "type": "string",
                        "description": "Raw unified diff text to analyze instead of invoking git diff"
                    },
                    "strict": {
                        "type": "boolean",
                        "description": "Fail on warnings as well as blockers"
                    }
                }
            }
        },
        {
            "name": "yupp_check_file",
            "description": "Run yupp static AST, test-theater, slop, and secret checks on a single file on disk.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "File path relative to repo_path (or absolute path)"
                    },
                    "repo_path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to current working directory)"
                    },
                    "strict": {
                        "type": "boolean",
                        "description": "Fail on warnings as well as blockers"
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "yupp_blast_radius",
            "description": "Find cross-file callers and test coverage for a symbol across a repository.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Function or method name to search callers for"
                    },
                    "file": {
                        "type": "string",
                        "description": "Optional defining file path (relative to repo_path) to exclude self-references"
                    },
                    "repo_path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to current working directory)"
                    }
                },
                "required": ["symbol"]
            }
        }
    ])
}

fn dispatch_tool(name: &str, args: &Value) -> Value {
    match name {
        "yupp_scan_diff" => tool_scan_diff(args),
        "yupp_check_file" => tool_check_file(args),
        "yupp_blast_radius" => tool_blast_radius(args),
        _ => tool_error(&format!("Unknown tool: {}", name)),
    }
}

fn tool_error(msg: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": msg }],
        "isError": true
    })
}

fn tool_scan_diff(args: &Value) -> Value {
    let started = Instant::now();
    let repo_root = args
        .get("repo_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let range = args.get("range").and_then(|v| v.as_str());
    let staged = args.get("staged").and_then(|v| v.as_bool()).unwrap_or(false);
    let raw_diff_arg = args.get("diff").and_then(|v| v.as_str());
    let strict_arg = args.get("strict").and_then(|v| v.as_bool());

    let raw_diff = if let Some(d) = raw_diff_arg {
        d.to_string()
    } else {
        let mut cmd = Command::new("git");
        cmd.current_dir(&repo_root).arg("diff").arg("--unified=3");
        if staged {
            cmd.arg("--cached");
        } else if let Some(r) = range {
            cmd.arg(r);
        }
        match cmd.output() {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
            Ok(out) => {
                return tool_error(&format!(
                    "git diff failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
            Err(e) => return tool_error(&format!("failed to run git diff: {}", e)),
        }
    };

    let config = match Config::load(&repo_root, None) {
        Ok(c) => c,
        Err(e) => return tool_error(&e),
    };
    let strict = strict_arg.or(config.strict).unwrap_or(false);
    let base_ref = if raw_diff_arg.is_some() {
        range.and_then(|r| resolve_base_ref(Some(r), false, &repo_root))
    } else {
        resolve_base_ref(range, staged, &repo_root)
    };

    let files = parse_unified_diff(&raw_diff);
    let lines_added: usize = files.iter().map(|f| f.added.len()).sum();
    let lines_removed: usize = files.iter().map(|f| f.removed.len()).sum();

    let opts = AnalyzeOptions { base_ref, config };
    let (findings, blast_radius) = analyze_diff_with_options(&files, &repo_root, &opts);
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

    let summary = render_terminal(&report, true);
    let payload = json!({
        "verdict": report.verdict,
        "summary": summary,
        "report": report
    });

    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
        }],
        "isError": false
    })
}

fn tool_check_file(args: &Value) -> Value {
    let started = Instant::now();
    let Some(file_arg) = args.get("file_path").and_then(|v| v.as_str()) else {
        return tool_error("Missing required argument `file_path`");
    };
    let repo_root = args
        .get("repo_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let strict_arg = args.get("strict").and_then(|v| v.as_bool());

    let candidate = Path::new(file_arg);
    let (full_path, rel_path) = if candidate.is_absolute() {
        let rel = candidate
            .strip_prefix(&repo_root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| file_arg.replace('\\', "/"));
        (candidate.to_path_buf(), rel)
    } else {
        (repo_root.join(candidate), file_arg.replace('\\', "/"))
    };

    let content = match fs::read_to_string(&full_path) {
        Ok(c) => c,
        Err(e) => return tool_error(&format!("failed to read {}: {}", full_path.display(), e)),
    };

    let added: Vec<DiffLine> = content
        .lines()
        .enumerate()
        .map(|(idx, line)| DiffLine {
            line_no: idx + 1,
            content: line.to_string(),
        })
        .collect();
    let lines_added = added.len();
    let files = vec![FileDiff {
        path: rel_path,
        added,
        removed: Vec::new(),
    }];

    let config = match Config::load(&repo_root, None) {
        Ok(c) => c,
        Err(e) => return tool_error(&e),
    };
    let strict = strict_arg.or(config.strict).unwrap_or(false);
    let opts = AnalyzeOptions {
        base_ref: None,
        config,
    };

    let (findings, blast_radius) = analyze_diff_with_options(&files, &repo_root, &opts);
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
        files_scanned: 1,
        lines_added,
        lines_removed: 0,
        elapsed_ms: started.elapsed().as_millis(),
        blockers,
        warnings,
        findings,
        blast_radius,
    };

    let payload = json!({
        "verdict": report.verdict,
        "summary": render_terminal(&report, true),
        "report": report
    });

    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
        }],
        "isError": false
    })
}

fn tool_blast_radius(args: &Value) -> Value {
    let Some(symbol) = args.get("symbol").and_then(|v| v.as_str()) else {
        return tool_error("Missing required argument `symbol`");
    };
    let repo_root = args
        .get("repo_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let def_file = args.get("file").and_then(|v| v.as_str());

    let entry = compute_symbol_blast_radius(&repo_root, symbol, def_file);
    let has_test_caller = entry.callers.iter().any(|c| c.is_test);
    let payload = json!({
        "symbol": entry.symbol,
        "file": entry.file,
        "caller_count": entry.callers.len(),
        "has_test_caller": has_test_caller,
        "callers": entry.callers
    });

    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
        }],
        "isError": false
    })
}
