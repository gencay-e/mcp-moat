use aho_corasick::AhoCorasick;
use regex::Regex;
use serde_json::Value;

pub struct DlpEngine {
    patterns: Vec<Regex>,
    keywords: AhoCorasick,
}

impl DlpEngine {
    pub fn new() -> Self {
        let patterns = vec![
            // Private Keys (PKCS#1, PKCS#8, OpenSSH, PGP, etc.) - non-capturing group
            Regex::new(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----").unwrap(),
            // AWS Access Key ID
            Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            // GitHub Personal Access Token
            Regex::new(r"\bghp_[0-9a-zA-Z]{36}\b").unwrap(),
            Regex::new(r"\bgithub_pat_[0-9a-zA-Z_]{70,95}\b").unwrap(),
            // Generic Secret keys (e.g. OpenAI sk-..., Anthropic sk-ant-..., Slack xoxb-...)
            Regex::new(r"\bsk-[a-zA-Z0-9_-]{20,}\b").unwrap(),
            // Stripe API Keys (sk_live_..., rk_live_..., sk_test_..., rk_test_...)
            Regex::new(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b").unwrap(),
            // GitHub OAuth and User Tokens (gho_..., ghu_..., ghs_..., ghr_...)
            Regex::new(r"\b(gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b").unwrap(),
            Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{24,}\b").unwrap(),
            // Google AI / Cloud API Keys (AIza...)
            Regex::new(r"\bAIza[0-9a-zA-Z_-]{30,40}\b").unwrap(),
            // Groq API keys (gsk_...)
            Regex::new(r"\bgsk_[0-9a-zA-Z]{20,}\b").unwrap(),
            // Hugging Face Tokens (hf_...)
            Regex::new(r"\bhf_[0-9a-zA-Z]{34}\b").unwrap(),
            // GitLab Personal Access Tokens (glpat-...)
            Regex::new(r"\bglpat-[0-9a-zA-Z_-]{20,}\b").unwrap(),
            // NPM Access Tokens (npm_...)
            Regex::new(r"\bnpm_[0-9a-zA-Z]{32,36}\b").unwrap(),
            // PyPI API Tokens (pypi-...)
            Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[0-9a-zA-Z-_]{50,}\b").unwrap(),
            // Bearer authorization tokens
            Regex::new(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{25,}\b").unwrap(),
            // Generic Password/Secret assignments in env style with named capture groups
            Regex::new(
                r#"(?i)\b(?P<key>(?:[a-z0-9]+[_-])*(?:api[_-]?key|secret[_-]?(?:access[_-]?)?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token|session[_-]?token|passwd|password)|(?:[a-z0-9]+[_-])+(?:secret|token))(?P<kq>['"]?)(?P<ws1>\s*)(?P<sep>[:=])(?P<ws2>\s*)(?P<vq>['"]?)(?P<val>[^\s'"]{8,})(?P<vq2>['"]?)"#,
            ).unwrap(),
        ];

        let sensitive_keywords = &[
            "BEGIN",
            "PRIVATE KEY",
            "AKIA",
            "ASIA",
            "ABIA",
            "ACCA",
            "ghp_",
            "github_pat_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "sk-",
            "sk_",
            "rk_",
            "sk-ant-",
            "AIza",
            "hf_",
            "gsk_",
            "glpat-",
            "npm_",
            "pypi-",
            "Bearer",
            "xoxb-",
            "xoxp-",
            "xoxa-",
            "xoxr-",
            "xoxs-",
            "password",
            "passwords",
            "secret",
            "secrets",
            "api_key",
            "api-key",
            "apikey",
            "apikeys",
            "client_secret",
            "auth_token",
            "authtokens",
            "access_token",
            "session_token",
            "passwd",
            "private_key",
            "token",
            "tokens",
            "auth",
            "authorization",
            "credential",
            "credentials",
            "keys",
        ];

        let keywords = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(sensitive_keywords)
            .unwrap();

        Self { patterns, keywords }
    }

    /// Fast scan to check if text might contain secrets
    pub fn contains_potential_secret(&self, text: &str) -> bool {
        self.keywords.is_match(text)
    }

    /// Redacts sensitive matches in a raw text string without breaking formatting
    pub fn sanitize_text(&self, text: &str) -> (String, usize) {
        if !self.contains_potential_secret(text) {
            return (text.to_string(), 0);
        }

        let mut sanitized = text.to_string();
        let mut redaction_count = 0;

        for pattern in &self.patterns {
            let replaced = pattern.replace_all(&sanitized, |caps: &regex::Captures| {
                redaction_count += 1;
                if let (Some(key), Some(sep)) = (caps.name("key"), caps.name("sep")) {
                    // Keep the name, quotes and spacing, so that `"KEY": "value"` stays readable.
                    let part = |name: &str| caps.name(name).map_or("", |m| m.as_str());
                    format!(
                        "{}{}{}{}{}{}[MCP-MOAT-REDACTED-SECRET]{}",
                        key.as_str(),
                        part("kq"),
                        part("ws1"),
                        sep.as_str(),
                        part("ws2"),
                        part("vq"),
                        part("vq2"),
                    )
                } else {
                    "[MCP-MOAT-REDACTED-SECRET]".to_string()
                }
            });
            if let std::borrow::Cow::Owned(s) = replaced {
                sanitized = s;
            }
        }

        (sanitized, redaction_count)
    }

    /// Recursively redacts strings inside a JSON value (AST-DLP)
    pub fn sanitize_json_value(&self, val: &mut Value) -> usize {
        match val {
            Value::String(s) => {
                let (redacted, count) = self.sanitize_text(s);
                if count > 0 {
                    *s = redacted;
                }
                count
            }
            Value::Array(arr) => {
                let mut total = 0;
                for item in arr {
                    total += self.sanitize_json_value(item);
                }
                total
            }
            Value::Object(map) => {
                let mut total = 0;
                let mut renames = Vec::new();
                for (k, v) in map.iter_mut() {
                    let k_norm = k.to_lowercase().replace(['_', '-'], "");
                    let is_secret_key = matches!(
                        k_norm.as_str(),
                        "password"
                            | "passwords"
                            | "passwd"
                            | "apikey"
                            | "apikeys"
                            | "secretkey"
                            | "secretkeys"
                            | "clientsecret"
                            | "clientsecrets"
                            | "authtoken"
                            | "authtokens"
                            | "accesstoken"
                            | "accesstokens"
                            | "sessiontoken"
                            | "sessiontokens"
                            | "privatekey"
                            | "privatekeys"
                            | "secret"
                            | "secrets"
                            | "token"
                            | "tokens"
                            | "bearer"
                            | "auth"
                            | "authorization"
                            | "credential"
                            | "credentials"
                            | "keys"
                    ) || k_norm.ends_with("password")
                        || k_norm.ends_with("passwords")
                        || k_norm.ends_with("passwd")
                        || k_norm.ends_with("secret")
                        || k_norm.ends_with("secrets")
                        || k_norm.ends_with("apikey")
                        || k_norm.ends_with("apikeys")
                        || k_norm.ends_with("authtoken")
                        || k_norm.ends_with("authtokens")
                        || k_norm.ends_with("token")
                        || k_norm.ends_with("tokens")
                        || k_norm.ends_with("credential")
                        || k_norm.ends_with("credentials")
                        || k_norm.ends_with("authorization")
                        || k_norm.starts_with("secret")
                        || k_norm.starts_with("apikey")
                        || k_norm.starts_with("credential");

                    if is_secret_key {
                        match v {
                            Value::String(s) => {
                                if !s.is_empty() && s != "[MCP-MOAT-REDACTED-SECRET]" {
                                    *s = "[MCP-MOAT-REDACTED-SECRET]".to_string();
                                    total += 1;
                                }
                            }
                            Value::Array(arr) => {
                                for item in arr.iter_mut() {
                                    if let Value::String(s) = item {
                                        if !s.is_empty() && s != "[MCP-MOAT-REDACTED-SECRET]" {
                                            *s = "[MCP-MOAT-REDACTED-SECRET]".to_string();
                                            total += 1;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    total += self.sanitize_json_value(v);
                    let (redacted_k, k_count) = self.sanitize_text(k);
                    if k_count > 0 {
                        renames.push((k.clone(), redacted_k));
                        total += k_count;
                    }
                }
                for (old_k, new_k) in renames {
                    if let Some(val) = map.remove(&old_k) {
                        map.insert(new_k, val);
                    }
                }
                total
            }
            _ => 0,
        }
    }

    /// Parses line as JSON-RPC AST if possible to avoid breaking JSON framing and defeat Unicode escapes
    pub fn sanitize_line(&self, line: &str) -> (String, usize) {
        // Fast-path pre-filter: Skip AST parsing entirely if no keyword and no unicode escape
        if !self.keywords.is_match(line) && !line.contains(r"\u") {
            return (line.to_string(), 0);
        }

        if let Ok(mut val) = serde_json::from_str::<Value>(line) {
            let count = self.sanitize_json_value(&mut val);
            if count > 0 {
                if let Ok(serialized) = serde_json::to_string(&val) {
                    return (serialized, count);
                }
            }
            return (line.to_string(), count);
        }

        // Fallback for non-JSON lines (e.g. raw stderr output)
        self.sanitize_text(line)
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlp_secret_masking() {
        let dlp = DlpEngine::new();
        let input = "DATABASE_URL=postgres://user:password12345@localhost/db\nAPI_KEY=sk-1234567890abcdef1234567890abcdef";
        let (output, count) = dlp.sanitize_text(input);
        assert!(count >= 1);
        assert!(!output.contains("sk-1234567890abcdef1234567890abcdef"));
        assert!(output.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_pkcs8_private_key_no_panic() {
        let dlp = DlpEngine::new();
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"}]}}"#;
        let (out, count) = dlp.sanitize_line(line);
        assert!(count >= 1);
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_json_framing_preserved() {
        let dlp = DlpEngine::new();
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"password=hunter2secret"}]}}"#;
        let (out, count) = dlp.sanitize_line(line);
        assert!(count > 0);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("Must remain valid JSON");
        assert!(parsed.to_string().contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_unicode_escaped_secret_masked() {
        let dlp = DlpEngine::new();
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"\u0073\u006b-1234567890abcdef1234567890abcdef"}]}}"#;
        let (out, count) = dlp.sanitize_line(line);
        assert!(count > 0);
        assert!(!out.contains("sk-1234567890abcdef"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_google_anthropic_huggingface() {
        let dlp = DlpEngine::new();
        let sample = "google: AIzaSyD12345678901234567890123456789012, anthropic: sk-ant-api03-1234567890abcdef1234567890abcdef, hf: hf_AbcDefGhIjKlMnOpQrStUvWxYz12345678";
        let (out, count) = dlp.sanitize_text(sample);
        assert_eq!(count, 3);
        assert!(!out.contains("AIzaSyD12345678901234567890123456789012"));
        assert!(!out.contains("sk-ant-api03-1234567890abcdef1234567890abcdef"));
        assert!(!out.contains("hf_AbcDefGhIjKlMnOpQrStUvWxYz12345678"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_gitlab_npm_pypi_bearer() {
        let dlp = DlpEngine::new();
        let sample = "gl: glpat-1234567890abcdefghij, npm: npm_1234567890abcdef1234567890abcdef, pypi: pypi-AgEIcHlwaS5vcmc12345678901234567890123456789012345678901234567890, auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        let (out, count) = dlp.sanitize_text(sample);
        assert_eq!(count, 4);
        assert!(!out.contains("glpat-1234567890abcdefghij"));
        assert!(!out.contains("npm_1234567890abcdef1234567890abcdef"));
        assert!(!out.contains("pypi-AgEIcHlwaS5vcmc"));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_stripe_and_github_oauth() {
        let dlp = DlpEngine::new();
        let sample = "stripe: sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz12345, restricted: rk_test_51AbcDefGhIjKlMnOpQrStUvWxYz12345, gho: gho_1234567890abcdef1234567890abcdef1234";
        let (out, count) = dlp.sanitize_text(sample);
        assert_eq!(count, 3);
        assert!(!out.contains("sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz12345"));
        assert!(!out.contains("rk_test_51AbcDefGhIjKlMnOpQrStUvWxYz12345"));
        assert!(!out.contains("gho_1234567890abcdef1234567890abcdef1234"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }
}
