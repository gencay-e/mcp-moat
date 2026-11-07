use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

fn deserialize_optional_id<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Value::deserialize(deserializer)?))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default, deserialize_with = "deserialize_optional_id")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;

    // Custom mcp-moat policy codes
    pub const POLICY_DENIED: i64 = -32001;
    pub const OPERATOR_REJECTED: i64 = -32002;

    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self {
            code: Self::POLICY_DENIED,
            message: format!("[mcp-moat security violation]: {}", msg.into()),
            data: None,
        }
    }

    pub fn operator_rejected(msg: impl Into<String>) -> Self {
        Self {
            code: Self::OPERATOR_REJECTED,
            message: format!("[mcp-moat rejected by operator]: {}", msg.into()),
            data: None,
        }
    }
}

impl JsonRpcResponse {
    pub fn error_response(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Helper for MCP tool call rejection formatted as normal tool result with isError=true
    pub fn tool_error_result(id: Option<Value>, reason: impl Into<String>) -> Self {
        let text_content = serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": format!(
                        "[MCP-MOAT: IMMUTABLE_POLICY_VIOLATION]\nAction blocked: {}\n\nINSTRUCTION FOR AGENT:\n1. This restriction is enforced by an external OS-level security proxy.\n2. DO NOT retry with alternative paths, encodings, or shell scripts.\n3. ABORT this subtask immediately and report the restriction to the user.",
                        reason.into()
                    )
                }
            ],
            "isError": true
        });

        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(text_content),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceParams {
    pub uri: String,
}

impl JsonRpcRequest {
    /// Returns true if this request is a notification (i.e. 'id' member was omitted completely)
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Returns true if this request targets the MCP tool call method
    pub fn is_tool_call(&self) -> bool {
        self.method == "tools/call"
    }

    /// Attempts to parse the parameters of a tool call
    pub fn parse_tool_call(&self) -> Option<ToolCallParams> {
        if self.is_tool_call() {
            if let Some(params) = &self.params {
                return serde_json::from_value::<ToolCallParams>(params.clone()).ok();
            }
        }
        None
    }

    /// Returns true if this request targets MCP resource methods (resources/read or resources/subscribe)
    pub fn is_resource_call(&self) -> bool {
        self.method == "resources/read" || self.method == "resources/subscribe"
    }

    /// Attempts to parse the parameters of a resource call
    pub fn parse_resource_call(&self) -> Option<ResourceParams> {
        if self.is_resource_call() {
            if let Some(params) = &self.params {
                return serde_json::from_value::<ResourceParams>(params.clone()).ok();
            }
        }
        None
    }
}

fn hex_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes percent-encoded characters (%20, %2e, etc.) into UTF-8 string
pub fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!("Incomplete percent-encoding in URI: '{}'", input));
            }
            let high = hex_to_nibble(bytes[i + 1]).ok_or_else(|| {
                format!(
                    "Invalid hex digit '%{}' in percent-encoded URI",
                    bytes[i + 1] as char
                )
            })?;
            let low = hex_to_nibble(bytes[i + 2]).ok_or_else(|| {
                format!(
                    "Invalid hex digit '%{}' in percent-encoded URI",
                    bytes[i + 2] as char
                )
            })?;
            let byte = (high << 4) | low;
            if byte == 0 {
                return Err("Null bytes (%00) are strictly prohibited in file URIs".to_string());
            }
            decoded.push(byte);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|e| format!("Invalid UTF-8 sequence after percent-decoding: {}", e))
}

/// Parses and validates a file:// URI into a native PathBuf.
///
/// Features:
/// - Verifies `file://` scheme (case-insensitive)
/// - Rejects remote hosts and UNC network paths (e.g. `file://remote/share`, `file:////server/share`)
/// - Rejects NT Object Manager namespace paths (`\??\`, `/device/`, etc.)
/// - Decodes RFC 3986 percent-encodings (`%20`, `%2e`, etc.)
/// - Converts `file:///C:/foo` or `file:///etc/foo` into native `PathBuf`
pub fn parse_file_uri_to_path(uri: &str) -> Result<PathBuf, String> {
    let trimmed = uri.trim();
    let lower = trimmed.to_ascii_lowercase();

    // 1. Verify scheme
    if !lower.starts_with("file://") {
        return Err(format!(
            "Invalid URI scheme in '{}': must start with 'file://'",
            uri
        ));
    }

    let after_scheme = &trimmed[7..];
    if after_scheme.is_empty() {
        return Err("Invalid file URI: missing path component".to_string());
    }

    // 2. Separate authority (host) from path
    let (authority, raw_path) = if let Some(slash_idx) = after_scheme.find('/') {
        (&after_scheme[..slash_idx], &after_scheme[slash_idx..])
    } else {
        return Err("Invalid file URI: missing path component".to_string());
    };

    // 3. Check authority: reject remote hosts (UNC)
    let auth_decoded = percent_decode(authority)?;
    let is_drive_auth = auth_decoded.len() == 2
        && auth_decoded.as_bytes()[0].is_ascii_alphabetic()
        && (auth_decoded.as_bytes()[1] == b':' || auth_decoded.as_bytes()[1] == b'|');

    if !auth_decoded.is_empty() && !auth_decoded.eq_ignore_ascii_case("localhost") && !is_drive_auth
    {
        return Err(format!(
            "Remote host or UNC path '{}' in file URI is strictly prohibited",
            auth_decoded
        ));
    }

    // 4. Decode percent-encoding in path
    let decoded_path = percent_decode(raw_path)?;

    // Reject double-encoded path separators and dots (%252e, %252f, %255c, %2500)
    let lower_decoded = decoded_path.to_ascii_lowercase();
    if lower_decoded.contains("%2e")
        || lower_decoded.contains("%2f")
        || lower_decoded.contains("%5c")
        || lower_decoded.contains("%00")
    {
        return Err(
            "Double percent-encoded traversal sequences are strictly prohibited".to_string(),
        );
    }

    // 5. Reject UNC and NT namespace paths in decoded path
    let lower_path = decoded_path.to_ascii_lowercase();
    if decoded_path.starts_with("//")
        || decoded_path.starts_with(r"\\")
        || decoded_path.starts_with(r"/\")
        || decoded_path.starts_with(r"\/")
        || decoded_path.starts_with(r"\??\")
        || decoded_path.starts_with("/??/")
        || decoded_path.starts_with(r"/??\")
        || decoded_path.starts_with(r"\??/")
        || lower_path.starts_with(r"\device\")
        || lower_path.starts_with("/device/")
        || lower_path.starts_with(r"/device\")
        || lower_path.starts_with(r"\device/")
    {
        return Err(format!(
            "UNC network and device namespace paths are strictly prohibited: '{}'",
            decoded_path
        ));
    }

    // 6. Handle Windows drive letter (e.g. "/C:/foo" -> "C:/foo", "/C|/foo" -> "C:/foo")
    let path_str = if is_drive_auth {
        let drive = auth_decoded.replace('|', ":");
        format!("{}{}", drive, decoded_path)
    } else if decoded_path.len() >= 3
        && decoded_path.starts_with('/')
        && decoded_path.as_bytes()[1].is_ascii_alphabetic()
        && (decoded_path.as_bytes()[2] == b':' || decoded_path.as_bytes()[2] == b'|')
        && (decoded_path.len() == 3
            || decoded_path.as_bytes()[3] == b'/'
            || decoded_path.as_bytes()[3] == b'\\')
    {
        let mut s = decoded_path[1..].to_string();
        if s.as_bytes()[1] == b'|' {
            s.replace_range(1..2, ":");
        }
        s
    } else {
        decoded_path
    };

    // 7. Convert to native PathBuf with platform-appropriate separators
    let native_str = if cfg!(windows) {
        path_str.replace('/', "\\")
    } else {
        path_str
    };

    Ok(PathBuf::from(native_str))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_resource_call() {
        let read_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "resources/read".to_string(),
            params: Some(json!({"uri": "file:///C:/foo/bar.txt"})),
        };
        assert!(read_req.is_resource_call());
        assert!(!read_req.is_tool_call());
        let res_params = read_req
            .parse_resource_call()
            .expect("Must parse resource params");
        assert_eq!(res_params.uri, "file:///C:/foo/bar.txt");

        let subscribe_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "resources/subscribe".to_string(),
            params: Some(json!({"uri": "file:///etc/hosts"})),
        };
        assert!(subscribe_req.is_resource_call());
        let sub_params = subscribe_req
            .parse_resource_call()
            .expect("Must parse subscribe params");
        assert_eq!(sub_params.uri, "file:///etc/hosts");

        let list_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "resources/list".to_string(),
            params: None,
        };
        assert!(!list_req.is_resource_call());
        assert!(list_req.parse_resource_call().is_none());

        let tool_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "tools/call".to_string(),
            params: Some(json!({"name": "read_file", "arguments": {"path": "foo"}})),
        };
        assert!(!tool_req.is_resource_call());
        assert!(tool_req.parse_resource_call().is_none());
    }

    #[test]
    fn test_request_id_deserialization() {
        let req_int: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":0,"method":"test"}"#).unwrap();
        assert_eq!(req_int.id, Some(json!(0)));
        assert!(!req_int.is_notification());

        let req_neg: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":-42,"method":"test"}"#).unwrap();
        assert_eq!(req_neg.id, Some(json!(-42)));
        assert!(!req_neg.is_notification());

        let req_u64: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"test"}"#)
                .unwrap();
        assert_eq!(req_u64.id, Some(json!(18446744073709551615u64)));
        assert!(!req_u64.is_notification());

        let req_float: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":42.5,"method":"test"}"#).unwrap();
        assert_eq!(req_float.id, Some(json!(42.5)));
        assert!(!req_float.is_notification());

        let req_str: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":"abc","method":"test"}"#).unwrap();
        assert_eq!(req_str.id, Some(json!("abc")));
        assert!(!req_str.is_notification());

        let req_null: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":null,"method":"test"}"#).unwrap();
        assert_eq!(req_null.id, Some(Value::Null));
        assert!(!req_null.is_notification());

        let req_none: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"test"}"#).unwrap();
        assert_eq!(req_none.id, None);
        assert!(req_none.is_notification());
    }

    #[test]
    fn test_parse_file_uri_windows_and_unix() {
        if cfg!(windows) {
            let p1 = parse_file_uri_to_path("file:///C:/foo/bar.txt").unwrap();
            assert_eq!(p1, PathBuf::from(r"C:\foo\bar.txt"));

            let p2 = parse_file_uri_to_path("file:///C:/foo%20bar/baz%2etxt").unwrap();
            assert_eq!(p2, PathBuf::from(r"C:\foo bar\baz.txt"));

            let p3 = parse_file_uri_to_path("file://localhost/D:/test/file").unwrap();
            assert_eq!(p3, PathBuf::from(r"D:\test\file"));

            let p_unix = parse_file_uri_to_path("file:///etc/foo").unwrap();
            assert_eq!(p_unix, PathBuf::from(r"\etc\foo"));
        } else {
            let p1 = parse_file_uri_to_path("file:///etc/foo").unwrap();
            assert_eq!(p1, PathBuf::from("/etc/foo"));

            let p2 = parse_file_uri_to_path("file:///etc/foo%20bar/baz%2etxt").unwrap();
            assert_eq!(p2, PathBuf::from("/etc/foo bar/baz.txt"));

            let p3 = parse_file_uri_to_path("file://localhost/etc/config").unwrap();
            assert_eq!(p3, PathBuf::from("/etc/config"));
        }
    }

    #[test]
    fn test_parse_file_uri_rejections() {
        // UNC via host authority
        assert!(parse_file_uri_to_path("file://remote-host/share/file").is_err());
        assert!(parse_file_uri_to_path("file://192.168.1.100/c$/secret").is_err());

        // UNC via leading slashes
        assert!(parse_file_uri_to_path("file:////server/share").is_err());
        assert!(parse_file_uri_to_path("file:///\\\\server/share").is_err());
        assert!(parse_file_uri_to_path("file:///%2f%2fserver/share").is_err());

        // NT namespace paths
        assert!(parse_file_uri_to_path("file:///??/C:/secret").is_err());
        assert!(parse_file_uri_to_path("file:///device/harddisk0").is_err());

        // Invalid scheme
        assert!(parse_file_uri_to_path("http://localhost/foo").is_err());
        assert!(parse_file_uri_to_path("https://example.com").is_err());

        // Missing path
        assert!(parse_file_uri_to_path("file://").is_err());
        assert!(parse_file_uri_to_path("file://localhost").is_err());

        // Null bytes
        assert!(parse_file_uri_to_path("file:///C:/foo%00bar").is_err());

        // Malformed percent-encoding
        assert!(parse_file_uri_to_path("file:///C:/foo%2").is_err());
        assert!(parse_file_uri_to_path("file:///C:/foo%ZZ").is_err());

        // Double percent-encoded traversal sequences (%252e -> %2e -> .)
        assert!(parse_file_uri_to_path("file:///C:/test/%252e%252e/Windows").is_err());
        assert!(parse_file_uri_to_path("file:///C:/test/%252f/Windows").is_err());
        assert!(parse_file_uri_to_path("file:///C:/test/%255c/Windows").is_err());
    }
}
