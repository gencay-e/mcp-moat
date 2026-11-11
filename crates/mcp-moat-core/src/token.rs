use crate::policy::PolicyEngine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Statistics returned by a single pass of the TokenOptimizer on an outbound JSON-RPC line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOptimizationStats {
    pub original_bytes: usize,
    pub optimized_bytes: usize,
    pub tools_pruned: usize,
    pub schemas_compacted: usize,
    pub outputs_truncated: usize,
}

impl TokenOptimizationStats {
    pub fn bytes_saved(&self) -> usize {
        self.original_bytes.saturating_sub(self.optimized_bytes)
    }

    pub fn modified(&self) -> bool {
        self.tools_pruned > 0 || self.schemas_compacted > 0 || self.outputs_truncated > 0
    }
}

/// Output format for Code-Mode (Programmatic Tool Calling) schema compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodegenFormat {
    TypeScript,
    Python,
    CompactMarkdown,
}

impl std::str::FromStr for CodegenFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ts" | "typescript" | "d.ts" => Ok(CodegenFormat::TypeScript),
            "py" | "python" => Ok(CodegenFormat::Python),
            "md" | "markdown" | "compact-md" | "skill" => Ok(CodegenFormat::CompactMarkdown),
            other => Err(format!(
                "Unsupported codegen format '{}'. Expected: ts, python, or compact-md",
                other
            )),
        }
    }
}

/// Summary report produced when compiling MCP `tools/list` schemas into Code-Mode stubs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodegenReport {
    pub format: CodegenFormat,
    pub output: String,
    pub raw_bytes: usize,
    pub compiled_bytes: usize,
    pub raw_estimated_tokens: usize,
    pub compiled_estimated_tokens: usize,
    pub savings_percent: f64,
    pub tools_included: usize,
    pub tools_filtered: usize,
}

/// Safely slices a UTF-8 string up to `max_bytes` without panicking on multi-byte codepoints.
pub fn truncate_utf8_safe(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Compacts a human-readable description to its concise first sentence or `max_chars` characters.
pub fn compact_description(desc: &str, max_chars: usize) -> String {
    let collapsed: String = desc.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return collapsed;
    }

    // Extract first sentence if it ends reasonably early
    let first_sentence = if let Some(idx) = collapsed.find(". ") {
        &collapsed[..=idx]
    } else {
        collapsed.as_str()
    };

    if first_sentence.chars().count() <= max_chars {
        return first_sentence.to_string();
    }

    let truncated: String = first_sentence
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect();
    format!("{}…", truncated.trim_end())
}

/// Recursively strips redundant JSON Schema metadata (`$schema`, `title`, `examples`, `default`)
/// and compacts verbose property descriptions to minimize LLM prompt token overhead.
fn slim_json_schema(schema: &mut Value, max_prop_desc_chars: usize) {
    if let Value::Object(map) = schema {
        map.remove("$schema");
        map.remove("title");
        map.remove("examples");
        map.remove("default");
        map.remove("$id");
        map.remove("$comment");

        if let Some(Value::String(desc)) = map.get_mut("description") {
            let compacted = compact_description(desc, max_prop_desc_chars);
            if compacted.is_empty() {
                map.remove("description");
            } else {
                *desc = compacted;
            }
        }

        // Remove empty `required: []` or `additionalProperties` if false/redundant
        if let Some(Value::Array(req)) = map.get("required") {
            if req.is_empty() {
                map.remove("required");
            }
        }

        if let Some(Value::Object(props)) = map.get_mut("properties") {
            for (_prop_name, prop_schema) in props.iter_mut() {
                slim_json_schema(prop_schema, max_prop_desc_chars);
            }
        }

        if let Some(items) = map.get_mut("items") {
            slim_json_schema(items, max_prop_desc_chars);
        }

        for combinator in ["anyOf", "oneOf", "allOf"] {
            if let Some(Value::Array(arr)) = map.get_mut(combinator) {
                for sub in arr.iter_mut() {
                    slim_json_schema(sub, max_prop_desc_chars);
                }
            }
        }
    }
}

/// TokenOptimizer compacts outbound MCP JSON-RPC responses in-flight:
/// 1. Prunes `hidden_tools` and (when `read_only` + `compact_schemas` are active) modifying tools from `tools/list`.
/// 2. Compacts bloated `tools/list` descriptions and `inputSchema` ASTs (`compact_schemas`).
/// 3. Enforces a context-window budget (`max_output_bytes`) on `tools/call` and `resources/read` outputs.
pub struct TokenOptimizer;

impl TokenOptimizer {
    /// Optimizes a single outbound JSON-RPC line according to policy settings.
    pub fn optimize_line(line: &str, policy: &PolicyEngine) -> (String, TokenOptimizationStats) {
        let cfg = policy.config();
        let has_hidden = !cfg.hidden_tools.is_empty();
        let do_schema_compact = cfg.compact_schemas;
        let max_out = cfg.max_output_bytes.filter(|&b| b > 0);

        let mut stats = TokenOptimizationStats {
            original_bytes: line.len(),
            optimized_bytes: line.len(),
            ..Default::default()
        };

        // Fast-path exit when no token optimization features are active
        if !has_hidden && !do_schema_compact && max_out.is_none() {
            return (line.to_string(), stats);
        }

        // Fast substring check before parsing JSON AST
        let maybe_tools_list = (has_hidden || do_schema_compact) && line.contains("\"tools\"");
        let maybe_content_output =
            max_out.is_some() && (line.contains("\"content\"") || line.contains("\"contents\""));

        if !maybe_tools_list && !maybe_content_output {
            return (line.to_string(), stats);
        }

        let mut root: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return (line.to_string(), stats),
        };

        let result_obj = match root.get_mut("result").and_then(|r| r.as_object_mut()) {
            Some(obj) => obj,
            None => return (line.to_string(), stats),
        };

        // 1. Handle `tools/list` response optimization
        if maybe_tools_list {
            if let Some(Value::Array(tools)) = result_obj.get_mut("tools") {
                let initial_len = tools.len();
                tools.retain(|tool| {
                    let name = tool
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_default();
                    if policy.is_tool_hidden(name) {
                        return false;
                    }
                    if do_schema_compact && cfg.read_only && policy.is_modifying_tool(name) {
                        return false;
                    }
                    true
                });
                stats.tools_pruned = initial_len.saturating_sub(tools.len());

                if do_schema_compact {
                    for tool in tools.iter_mut() {
                        if let Value::Object(tmap) = tool {
                            if let Some(Value::String(desc)) = tmap.get_mut("description") {
                                *desc = compact_description(desc, 140);
                            }
                            if let Some(schema) = tmap.get_mut("inputSchema") {
                                slim_json_schema(schema, 80);
                            }
                            tmap.remove("annotations");
                            stats.schemas_compacted += 1;
                        }
                    }
                }
            }
        }

        // 2. Handle `tools/call` (`result.content`) & `resources/read` (`result.contents`) budget
        if let Some(limit) = max_out {
            for key in ["content", "contents"] {
                if let Some(Value::Array(items)) = result_obj.get_mut(key) {
                    for item in items.iter_mut() {
                        if let Some(Value::String(text)) =
                            item.as_object_mut().and_then(|o| o.get_mut("text"))
                        {
                            if text.len() > limit {
                                let excess = text.len() - limit;
                                let safe_prefix = truncate_utf8_safe(text, limit).to_string();
                                *text = format!(
                                    "{}\n...[MCP-MOAT TOKEN GUARD: truncated {} bytes (context budget: {} bytes). Refine query or use line ranges.]",
                                    safe_prefix, excess, limit
                                );
                                stats.outputs_truncated += 1;
                            }
                        }
                    }
                }
            }
        }

        if stats.modified() {
            if let Ok(serialized) = serde_json::to_string(&root) {
                stats.optimized_bytes = serialized.len();
                return (serialized, stats);
            }
        }

        (line.to_string(), stats)
    }

    /// Compiles an MCP `tools/list` JSON payload (either full JSON-RPC response or `{"tools": [...]}`)
    /// into compact Code-Mode declarations (TypeScript SDK, Python stubs, or Compact Markdown).
    pub fn compile_code_mode(
        tools_payload: &Value,
        policy: &PolicyEngine,
        format: CodegenFormat,
    ) -> Result<CodegenReport, String> {
        let tools_arr = tools_payload
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .or_else(|| tools_payload.get("tools").and_then(|t| t.as_array()))
            .or_else(|| tools_payload.as_array())
            .ok_or_else(|| {
                "Expected MCP tools/list JSON containing 'result.tools' or 'tools' array"
                    .to_string()
            })?;

        let raw_serialized = serde_json::to_string(tools_arr).unwrap_or_default();
        let raw_bytes = raw_serialized.len();

        let mut allowed_tools = Vec::new();
        let mut tools_filtered = 0usize;

        for tool in tools_arr {
            let name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            if policy.is_tool_hidden(name)
                || (policy.config().read_only && policy.is_modifying_tool(name))
            {
                tools_filtered += 1;
                continue;
            }
            allowed_tools.push(tool);
        }

        let output = match format {
            CodegenFormat::TypeScript => render_typescript_sdk(&allowed_tools),
            CodegenFormat::Python => render_python_stubs(&allowed_tools),
            CodegenFormat::CompactMarkdown => render_compact_markdown(&allowed_tools),
        };

        let compiled_bytes = output.len();
        let raw_estimated_tokens = raw_bytes.div_ceil(4);
        let compiled_estimated_tokens = compiled_bytes.div_ceil(4);
        let savings_percent = if raw_bytes > 0 && compiled_bytes < raw_bytes {
            ((raw_bytes - compiled_bytes) as f64 / raw_bytes as f64) * 100.0
        } else {
            0.0
        };

        Ok(CodegenReport {
            format,
            output,
            raw_bytes,
            compiled_bytes,
            raw_estimated_tokens,
            compiled_estimated_tokens,
            savings_percent,
            tools_included: allowed_tools.len(),
            tools_filtered,
        })
    }
}

fn sanitize_identifier(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "tool".to_string()
    } else {
        out
    }
}

fn json_type_to_ts(prop: &Value) -> String {
    if let Some(Value::Array(enums)) = prop.get("enum") {
        let literals: Vec<String> = enums
            .iter()
            .filter_map(|v| v.as_str().map(|s| format!("\"{}\"", s)))
            .collect();
        if !literals.is_empty() {
            return literals.join(" | ");
        }
    }

    match prop.get("type").and_then(|t| t.as_str()) {
        Some("string") => "string".to_string(),
        Some("number") | Some("integer") => "number".to_string(),
        Some("boolean") => "boolean".to_string(),
        Some("array") => {
            let item_ts = prop
                .get("items")
                .map(json_type_to_ts)
                .unwrap_or_else(|| "unknown".to_string());
            format!("{}[]", item_ts)
        }
        Some("object") => "Record<string, unknown>".to_string(),
        _ => "unknown".to_string(),
    }
}

fn json_type_to_py(prop: &Value) -> String {
    match prop.get("type").and_then(|t| t.as_str()) {
        Some("string") => "str".to_string(),
        Some("integer") => "int".to_string(),
        Some("number") => "float".to_string(),
        Some("boolean") => "bool".to_string(),
        Some("array") => {
            let item_py = prop
                .get("items")
                .map(json_type_to_py)
                .unwrap_or_else(|| "Any".to_string());
            format!("list[{}]", item_py)
        }
        Some("object") => "dict[str, Any]".to_string(),
        _ => "Any".to_string(),
    }
}

fn extract_schema_props(tool: &Value) -> (Option<&Map<String, Value>>, Vec<&str>) {
    let schema = tool.get("inputSchema");
    let props = schema
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object());
    let required: Vec<&str> = schema
        .and_then(|s| s.get("required"))
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    (props, required)
}

fn render_typescript_sdk(tools: &[&Value]) -> String {
    let mut lines = Vec::new();
    lines.push(
        "// Generated by mcp-moat from the server's tool list. Tools blocked by the policy are left out.".to_string(),
    );
    lines.push("declare namespace mcp {".to_string());

    for tool in tools {
        let raw_name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
        let fn_name = sanitize_identifier(raw_name);
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .map(|d| compact_description(d, 120))
            .unwrap_or_default();

        if !desc.is_empty() {
            lines.push(format!("  /** {} */", desc));
        }

        let (props_opt, required) = extract_schema_props(tool);
        if let Some(props) = props_opt {
            if props.is_empty() {
                lines.push(format!("  function {}(): Promise<unknown>;", fn_name));
            } else {
                let mut fields = Vec::new();
                for (k, v) in props {
                    let is_req = required.contains(&k.as_str());
                    let opt_mark = if is_req { "" } else { "?" };
                    let ts_ty = json_type_to_ts(v);
                    fields.push(format!("{}{}: {}", k, opt_mark, ts_ty));
                }
                lines.push(format!(
                    "  function {}(args: {{ {} }}): Promise<unknown>;",
                    fn_name,
                    fields.join("; ")
                ));
            }
        } else {
            lines.push(format!("  function {}(): Promise<unknown>;", fn_name));
        }
    }

    lines.push("}".to_string());
    lines.join("\n")
}

fn render_python_stubs(tools: &[&Value]) -> String {
    let mut lines = Vec::new();
    lines.push(
        "# Generated by mcp-moat from the server's tool list. Tools blocked by the policy are left out.".to_string(),
    );
    lines.push("from typing import Any".to_string());
    lines.push(String::new());

    for tool in tools {
        let raw_name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
        let fn_name = sanitize_identifier(raw_name);
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .map(|d| compact_description(d, 120))
            .unwrap_or_default();

        let (props_opt, required) = extract_schema_props(tool);
        let mut req_params = Vec::new();
        let mut opt_params = Vec::new();

        if let Some(props) = props_opt {
            for (k, v) in props {
                let py_ident = sanitize_identifier(k);
                let py_ty = json_type_to_py(v);
                if required.contains(&k.as_str()) {
                    req_params.push(format!("{}: {}", py_ident, py_ty));
                } else {
                    opt_params.push(format!("{}: {} | None = None", py_ident, py_ty));
                }
            }
        }

        req_params.extend(opt_params);
        let sig = req_params.join(", ");
        lines.push(format!("async def {}({}) -> Any:", fn_name, sig));
        if !desc.is_empty() {
            lines.push(format!("    \"\"\"{}\"\"\"", desc.replace('"', "'")));
        }
        lines.push("    ...".to_string());
        lines.push(String::new());
    }

    lines.join("\n").trim_end().to_string()
}

fn render_compact_markdown(tools: &[&Value]) -> String {
    let mut lines = Vec::new();
    lines.push("| Tool | Arguments | Summary |".to_string());
    lines.push("| :--- | :--- | :--- |".to_string());

    for tool in tools {
        let raw_name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .map(|d| compact_description(d, 100))
            .unwrap_or_default();

        let (props_opt, required) = extract_schema_props(tool);
        let args_str = if let Some(props) = props_opt {
            let mut parts = Vec::new();
            for (k, v) in props {
                let is_req = required.contains(&k.as_str());
                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("any");
                parts.push(format!("{}{}:{}", k, if is_req { "" } else { "?" }, ty));
            }
            if parts.is_empty() {
                "-".to_string()
            } else {
                format!("`{}`", parts.join(", "))
            }
        } else {
            "-".to_string()
        };

        lines.push(format!(
            "| `{}` | {} | {} |",
            raw_name,
            args_str,
            desc.replace('|', "\\|")
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyConfig;
    use serde_json::json;

    fn sample_bloated_tools_response() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Reads the complete contents of a file from the filesystem. This tool handles various text encodings and returns detailed error messages if the file cannot be read or does not exist inside the workspace.",
                        "inputSchema": {
                            "$schema": "http://json-schema.org/draft-07/schema#",
                            "title": "ReadFileParameters",
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "title": "FilePath",
                                    "description": "The full or relative path to the file on disk that should be read by the MCP filesystem server. Must be within allowed directories.",
                                    "examples": ["./README.md", "src/main.rs"]
                                }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "write_file",
                        "description": "Writes or overwrites a file on the filesystem with new content. Use with caution as existing contents will be lost permanently.",
                        "inputSchema": {
                            "$schema": "http://json-schema.org/draft-07/schema#",
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Target path to write." },
                                "content": { "type": "string", "description": "Text content to write." }
                            },
                            "required": ["path", "content"]
                        }
                    },
                    {
                        "name": "delete_file",
                        "description": "Permanently deletes a file from the disk.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" }
                            },
                            "required": ["path"]
                        }
                    }
                ]
            }
        })
    }

    #[test]
    fn test_schema_compaction_and_read_only_pruning() {
        let cfg = PolicyConfig {
            compact_schemas: true,
            read_only: true,
            ..PolicyConfig::default()
        };
        let policy = PolicyEngine::new(cfg).unwrap();

        let raw_line = serde_json::to_string(&sample_bloated_tools_response()).unwrap();
        let (optimized_line, stats) = TokenOptimizer::optimize_line(&raw_line, &policy);

        // write_file and delete_file must be pruned because read_only = true and compact_schemas = true
        assert_eq!(stats.tools_pruned, 2);
        assert_eq!(stats.schemas_compacted, 1);
        assert!(stats.bytes_saved() > 400);

        let parsed: Value = serde_json::from_str(&optimized_line).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "read_file");
        // Verify $schema, title, examples were stripped
        assert!(tools[0]["inputSchema"].get("$schema").is_none());
        assert!(tools[0]["inputSchema"].get("title").is_none());
        assert!(tools[0]["inputSchema"]["properties"]["path"]
            .get("examples")
            .is_none());
    }

    #[test]
    fn test_hidden_tools_pruned_from_tools_list() {
        let cfg = PolicyConfig {
            hidden_tools: vec!["delete_file".to_string()],
            ..PolicyConfig::default()
        };
        let policy = PolicyEngine::new(cfg).unwrap();

        let raw_line = serde_json::to_string(&sample_bloated_tools_response()).unwrap();
        let (optimized_line, stats) = TokenOptimizer::optimize_line(&raw_line, &policy);

        assert_eq!(stats.tools_pruned, 1);
        let parsed: Value = serde_json::from_str(&optimized_line).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().all(|t| t["name"] != "delete_file"));
    }

    #[test]
    fn test_output_budget_truncation_utf8_safe() {
        let cfg = PolicyConfig {
            max_output_bytes: Some(30),
            ..PolicyConfig::default()
        };
        let policy = PolicyEngine::new(cfg).unwrap();

        let resp = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Hello world! äöüß🔥 This is a very long tool output that has to be shortened."
                    }
                ]
            }
        });
        let raw_line = serde_json::to_string(&resp).unwrap();
        let (optimized_line, stats) = TokenOptimizer::optimize_line(&raw_line, &policy);

        assert_eq!(stats.outputs_truncated, 1);
        let parsed: Value = serde_json::from_str(&optimized_line).unwrap();
        let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("[MCP-MOAT TOKEN GUARD: truncated"));
    }

    #[test]
    fn test_codegen_typescript_and_python_savings() {
        let cfg = PolicyConfig {
            read_only: true,
            ..PolicyConfig::default()
        };
        let policy = PolicyEngine::new(cfg).unwrap();
        let payload = sample_bloated_tools_response();

        let ts_report =
            TokenOptimizer::compile_code_mode(&payload, &policy, CodegenFormat::TypeScript)
                .unwrap();
        assert_eq!(ts_report.tools_included, 1);
        assert_eq!(ts_report.tools_filtered, 2);
        assert!(ts_report.output.contains("declare namespace mcp {"));
        assert!(ts_report
            .output
            .contains("function read_file(args: { path: string }): Promise<unknown>;"));
        assert!(!ts_report.output.contains("write_file"));
        assert!(ts_report.savings_percent > 60.0);

        let py_report =
            TokenOptimizer::compile_code_mode(&payload, &policy, CodegenFormat::Python).unwrap();
        assert!(py_report
            .output
            .contains("async def read_file(path: str) -> Any:"));
    }
}
