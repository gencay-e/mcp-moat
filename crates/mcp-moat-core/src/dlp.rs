use aho_corasick::AhoCorasick;
use regex::Regex;
use serde_json::Value;

pub struct DlpEngine {
    patterns: Vec<Regex>,
    keywords: AhoCorasick,
    /// Masks long Base64 runs with mixed character classes. Off by default: it also matches
    /// image and audio data, lockfile hashes, long identifiers and public keys.
    base64_heuristic: bool,
}

impl DlpEngine {
    pub fn new() -> Self {
        let patterns = vec![
            // Private Keys (PKCS#1, PKCS#8, OpenSSH, PGP, etc.) - non-capturing group
            Regex::new(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----").unwrap(),
            // AWS Access Key ID, including temporary session credentials (ASIA...)
            Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            // GitHub Personal Access Token
            Regex::new(r"\bghp_[0-9a-zA-Z]{36}\b").unwrap(),
            Regex::new(r"\bgithub_pat_[0-9a-zA-Z_]{70,95}\b").unwrap(),
            // OpenAI project, service-account and admin keys
            Regex::new(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b").unwrap(),
            Regex::new(r"\bsk-svcacct-[A-Za-z0-9_-]{20,}\b").unwrap(),
            Regex::new(r"\bsk-admin-[A-Za-z0-9_-]{20,}\b").unwrap(),
            // DeepSeek API keys (sk- followed by 32 hex characters)
            Regex::new(r"\bsk-[0-9a-f]{32}\b").unwrap(),
            // Perplexity API keys (pplx-...)
            Regex::new(r"\bpplx-[A-Za-z0-9]{20,}\b").unwrap(),
            // Voyage AI keys: standalone (pa-...) and Atlas (al-, al-eu-, al-us-...)
            Regex::new(r"\bpa-[A-Za-z0-9_-]{40,}\b").unwrap(),
            Regex::new(r"\bal-[A-Za-z0-9_-]{40,}\b").unwrap(),
            // Cohere tokens (co_...)
            Regex::new(r"\bco_[A-Za-z0-9]{40,}\b").unwrap(),
            // Generic Secret keys (e.g. OpenAI sk-..., Anthropic sk-ant-..., Moonshot/Qwen sk-...)
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
            // Mistral API keys: 32 alphanumeric characters without a prefix, gated by "mistral" context
            Regex::new(r"(?i)\bmistral[a-z0-9_.\-]{0,40}\b[^\n]{0,80}?(?P<val>\b[A-Za-z0-9]{32}\b)").unwrap(),
            // Cohere tokens without the co_ prefix: 40 alphanumerics, gated by "cohere" context
            Regex::new(r"(?i)\bcohere\b[^\n]{0,80}?(?P<val>\b[A-Za-z0-9]{40}\b)").unwrap(),
            // AWS secret access keys (40 chars), gated by "aws" or "secret" context so that the
            // check also works without the Base64 heuristic
            Regex::new(r"(?i)\b(?:aws|secret)[a-z0-9_.\-]{0,40}\b[^\n]{0,40}?(?P<val>\b[A-Za-z0-9/+]{40}\b)").unwrap(),
            // Base64-encoded secrets (standard alphabet), validated by character-class heuristic
            Regex::new(r"(?P<pre>^|[^A-Za-z0-9+/])(?P<b64>[A-Za-z0-9+/]{40,}={0,2})").unwrap(),
            // Base64url-encoded secrets (URL-safe alphabet), validated by character-class heuristic
            // Hyphen at end of negated class to avoid being interpreted as range operator
            Regex::new(r"(?P<pre>^|[^A-Za-z0-9_-])(?P<b64>[A-Za-z0-9_-]{40,})").unwrap(),
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
            "sk-proj-",
            "sk-svcacct-",
            "sk-admin-",
            "pplx-",
            "pa-",
            "co_",
            "cohere",
            "mistral",
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

        Self {
            patterns,
            keywords,
            base64_heuristic: false,
        }
    }

    /// Enables the Base64 heuristic (`dlp_base64_heuristic = true` in `moat.toml`).
    pub fn with_base64_heuristic(mut self, enabled: bool) -> Self {
        self.base64_heuristic = enabled;
        self
    }

    /// Fast scan to check if text might contain secrets
    pub fn contains_potential_secret(&self, text: &str) -> bool {
        self.keywords.is_match(text)
            || (self.base64_heuristic && Self::might_contain_base64_secret(text))
    }

    /// Cheap pre-filter for the Base64 heuristic. Long runs of mixed-case
    /// alphanumerics are the only candidates worth running the regexes on.
    fn might_contain_base64_secret(text: &str) -> bool {
        if text.len() < 40 {
            return false;
        }
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        for byte in text.bytes() {
            if byte.is_ascii_uppercase() {
                has_upper = true;
            } else if byte.is_ascii_lowercase() {
                has_lower = true;
            } else if byte.is_ascii_digit() {
                has_digit = true;
            }
            if has_upper && has_lower && has_digit {
                return true;
            }
        }
        false
    }

    /// Heuristic for Base64/Base64url blobs that look like encoded secrets.
    /// Requires enough length and mixed character classes, which keeps hashes,
    /// identifiers and prose out while still catching encoded credentials.
    fn is_likely_base64_secret(candidate: &str) -> bool {
        let trimmed = candidate.trim_end_matches('=');
        if trimmed.len() < 40 {
            return false;
        }
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        for byte in trimmed.bytes() {
            if byte.is_ascii_uppercase() {
                has_upper = true;
            } else if byte.is_ascii_lowercase() {
                has_lower = true;
            } else if byte.is_ascii_digit() {
                has_digit = true;
            }
        }
        has_upper && has_lower && has_digit
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
                if let (Some(key), Some(sep)) = (caps.name("key"), caps.name("sep")) {
                    // Keep the name, quotes and spacing, so that `"KEY": "value"` stays readable.
                    redaction_count += 1;
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
                } else if let Some(b64) = caps.name("b64") {
                    if self.base64_heuristic && Self::is_likely_base64_secret(b64.as_str()) {
                        redaction_count += 1;
                        format!(
                            "{}[MCP-MOAT-REDACTED-SECRET]",
                            caps.name("pre").map_or("", |m| m.as_str())
                        )
                    } else {
                        caps.get(0).map_or("", |m| m.as_str()).to_string()
                    }
                } else if let Some(val) = caps.name("val") {
                    // Context-gated patterns (e.g. Mistral) only replace the value span.
                    redaction_count += 1;
                    let whole = caps.get(0).unwrap();
                    let start = val.start() - whole.start();
                    let end = val.end() - whole.start();
                    let text = whole.as_str();
                    format!(
                        "{}[MCP-MOAT-REDACTED-SECRET]{}",
                        &text[..start],
                        &text[end..]
                    )
                } else {
                    redaction_count += 1;
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
        // Fast-path pre-filter: skip AST parsing if nothing could possibly match.
        if !self.keywords.is_match(line)
            && !line.contains(r"\u")
            && !(self.base64_heuristic && Self::might_contain_base64_secret(line))
        {
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
        let g_tok = ["AIza", "SyD12345678901234567890123456789012"].concat();
        let ant_tok = ["sk-ant-api03", "1234567890abcdef1234567890abcdef"].join("-");
        let hf_tok = ["hf", "AbcDefGhIjKlMnOpQrStUvWxYz12345678"].join("_");
        let sample = format!("google: {g_tok}, anthropic: {ant_tok}, hf: {hf_tok}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert_eq!(count, 3);
        assert!(!out.contains(&g_tok));
        assert!(!out.contains(&ant_tok));
        assert!(!out.contains(&hf_tok));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_gitlab_npm_pypi_bearer() {
        let dlp = DlpEngine::new();
        let gl_tok = ["glpat", "1234567890abcdefghij"].join("-");
        let npm_tok = ["npm", "1234567890abcdef1234567890abcdef"].join("_");
        let pypi_tok = [
            "pypi",
            "AgEIcHlwaS5vcmc",
            "12345678901234567890123456789012345678901234567890",
        ]
        .join("-");
        let jwt_frag = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "e30",
            "t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
        ]
        .join(".");
        let sample =
            format!("gl: {gl_tok}, npm: {npm_tok}, pypi: {pypi_tok}, auth: Bearer {jwt_frag}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert_eq!(count, 4);
        assert!(!out.contains(&gl_tok));
        assert!(!out.contains(&npm_tok));
        assert!(!out.contains(&pypi_tok));
        assert!(!out.contains(&jwt_frag));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_stripe_and_github_oauth() {
        let dlp = DlpEngine::new();
        let stripe_tok = ["sk", "live", "51AbcDefGhIjKlMnOpQrStUvWxYz12345"].join("_");
        let rk_tok = ["rk", "test", "51AbcDefGhIjKlMnOpQrStUvWxYz12345"].join("_");
        let gho_tok = ["gho", "1234567890abcdef1234567890abcdef1234"].join("_");
        let sample = format!("stripe: {stripe_tok}, restricted: {rk_tok}, gho: {gho_tok}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert_eq!(count, 3);
        assert!(!out.contains(&stripe_tok));
        assert!(!out.contains(&rk_tok));
        assert!(!out.contains(&gho_tok));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_openai_project_svcacct_admin() {
        let dlp = DlpEngine::new();
        let proj_tok = ["sk", "proj", "AbCdEf0123456789AbCdEf0123456789"].join("-");
        let admin_tok = ["sk", "admin", "AbCdEf0123456789AbCdEf0123456789"].join("-");
        let svc_tok = ["sk", "svcacct", "AbCdEf0123456789AbCdEf0123456789"].join("-");
        let sample = format!("proj={proj_tok} admin={admin_tok} svc={svc_tok}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert!(count >= 3);
        assert!(!out.contains("sk-proj-AbCdEf"));
        assert!(!out.contains("sk-admin-AbCdEf"));
        assert!(!out.contains("sk-svcacct-AbCdEf"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_deepseek_and_perplexity() {
        let dlp = DlpEngine::new();
        let ds_tok = ["sk", "0123456789abcdef0123456789abcdef"].join("-");
        let pplx_tok = ["pplx", "AbCdEf0123456789AbCdEf0123456789"].join("-");
        let sample = format!("deepseek={ds_tok} perplexity={pplx_tok}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert!(count >= 2);
        assert!(!out.contains(&ds_tok));
        assert!(!out.contains(&pplx_tok));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_aws_session_token() {
        let dlp = DlpEngine::new();
        let sts_tok = ["ASIA", "IOSFODNN7EXAMPLE"].concat();
        let payload = format!("aws_session_token: {sts_tok}");
        let (out, count) = dlp.sanitize_text(&payload);
        assert!(count >= 1);
        assert!(!out.contains(&sts_tok));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_aws_secret_access_key_heuristic() {
        let dlp = DlpEngine::new();
        let secret = ["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"].join("/");

        let (out, count) = dlp.sanitize_text(&format!("secret: {}", secret));
        assert!(count >= 1, "Bare AWS secret access key must be caught");
        assert!(!out.contains(&secret));

        let (out2, count2) = dlp.sanitize_text(&format!("AWS_SECRET_ACCESS_KEY={}", secret));
        assert!(count2 >= 1, "Assigned AWS secret access key must be caught");
        assert!(!out2.contains(&secret));
    }

    #[test]
    fn test_dlp_voyage_and_cohere() {
        let dlp = DlpEngine::new();
        let body = ["AbCdEf0123456789", "AbCdEf0123456789", "AbCdEf012345"].concat();
        let sample = format!("voyage: pa-{body} atlas: al-{body} cohere: co_{body}");
        let (out, count) = dlp.sanitize_text(&sample);
        assert!(count >= 3);
        assert!(!out.contains(&format!("pa-{body}")));
        assert!(!out.contains(&format!("al-{body}")));
        assert!(!out.contains(&format!("co_{body}")));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_mistral_context_gated() {
        let dlp = DlpEngine::new();
        let mistral_body = ["AbCdEf0123456789", "AbCdEf0123456789"].concat();
        let sample = format!("Mistral {} key: {mistral_body}", "API");
        let (out, count) = dlp.sanitize_text(&sample);
        assert!(count >= 1);
        assert!(!out.contains(&mistral_body));
        assert!(out.contains("Mistral API key: [MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_base64_secret_heuristic() {
        let dlp = DlpEngine::new().with_base64_heuristic(true);
        let standard = [
            "QWxsIHlvdXIgYmFzZTY0IGFyZS",
            "BiZWxvbmcgdG8gdXMgMTIzNDU2Nzg5MA==",
        ]
        .concat();
        let url_safe = ["JUpvlLneAyhNcpe84QYrUHWav", "-QJLlN4ncLnDDFWe6DF6g80WX6jyA"].concat();
        let sample = format!("payload: {} url: {}", standard, url_safe);
        let (out, count) = dlp.sanitize_text(&sample);
        assert!(count >= 2);
        assert!(!out.contains(&standard));
        assert!(!out.contains(&url_safe));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_base64_heuristic_ignores_hex_hashes() {
        let dlp = DlpEngine::new();
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (out, count) = dlp.sanitize_text(&format!("hash: {}", sha256));
        assert_eq!(count, 0);
        assert!(out.contains(sha256));
    }

    #[test]
    fn test_dlp_base64_in_json_preserves_framing() {
        let dlp = DlpEngine::new().with_base64_heuristic(true);
        let secret = "dGVzdGJhc2U2NGtleQdGVzdGJhc2U2NGtleQdGVzdGJhc2U2NGtleQdGVzdA==";
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"data":"{}"}}}}"#,
            secret
        );
        let (out, count) = dlp.sanitize_line(&line);
        assert!(count >= 1);
        assert!(!out.contains(secret));
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert!(parsed.to_string().contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_base64_ignores_unix_pathlike() {
        let dlp = DlpEngine::new();
        let fake_path = "aGVscG1lbnQvY2hhcnRzL2tleQ==";
        let (out, count) = dlp.sanitize_text(&format!("path: {}", fake_path));
        assert_eq!(count, 0, "Base64-like string with / should not trigger");
        assert!(out.contains(fake_path));
    }

    #[test]
    fn test_dlp_base64_ignores_windows_pathlike() {
        let dlp = DlpEngine::new();
        let fake_path = "aGVscG1lbnAcY2hhcnRzAY2hYXJl";
        let (out, count) = dlp.sanitize_text(&format!("path: {}", fake_path));
        assert_eq!(count, 0, "Base64-like string with \\ should not trigger");
        assert!(out.contains(fake_path));
    }

    #[test]
    fn test_dlp_base64_ignores_ssh_private_key_block() {
        let dlp = DlpEngine::new();
        let sample = r#"-----BEGIN OPENSSH PRIVATE KEY-----
LS0tLS1BRUdJTiBQUklWQVRFIEtFWS0tLS0t
-----END OPENSSH PRIVATE KEY-----"#;
        let (out, count) = dlp.sanitize_text(sample);
        assert_eq!(
            count, 1,
            "SSH private key block should be redacted as one unit"
        );
        assert!(!out.contains("LS0tLS1BRUdJTiBQUklWQVRFIEtFWS0tLS0t"));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    #[test]
    fn test_dlp_base64_ignores_git_sha() {
        let dlp = DlpEngine::new();
        let git_sha = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";
        let (out, count) = dlp.sanitize_text(&format!("commit: {}", git_sha));
        assert_eq!(count, 0, "Git SHA-like hex string should not trigger");
        assert!(out.contains(git_sha));
    }

    #[test]
    fn test_dlp_base64_ignores_mime_boundary() {
        let dlp = DlpEngine::new();
        let boundary = "=_JjJwYOdKpE4dHvR2sT9uI1oP3mNB5vC7xK8yA0eFgH";
        let sample = format!("Content-Type: multipart/mixed; boundary={}", boundary);
        let (out, count) = dlp.sanitize_text(&sample);
        assert_eq!(count, 0, "MIME boundary should not trigger");
        assert!(out.contains(boundary));
    }

    #[test]
    fn test_dlp_base64_heuristic_is_off_by_default() {
        let dlp = DlpEngine::new();
        for sample in [
            "/home/gencay/Projects/MyApp2/src/components/Button.tsx",
            r#"{"type":"image","data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="}"#,
            r#"{"type":"audio","data":"UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA1"}"#,
            r#""integrity": "sha512-Xj2Kp9QmVb7Rr0uLWnT3yZ8fH1cA4sE6dG5hJ2kL0mN9oP8qR7sT6uV5wX4yZ3aB2cD1eF0gH==""#,
            "fn testParseHandlesVeryLongIdentifierName42Correctly() {}",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq1Xk4m7LxP0zQ8bR3sT5uV9wY2aC4dE6fG8hJ0kL1 user@host",
        ] {
            let (out, count) = dlp.sanitize_text(sample);
            assert_eq!(count, 0, "masked without opt-in: {sample}");
            assert_eq!(out, sample);
            let (line_out, line_count) = dlp.sanitize_line(sample);
            assert_eq!(line_count, 0, "masked without opt-in (line): {sample}");
            assert_eq!(line_out, sample);
        }
    }

    #[test]
    fn test_dlp_base64_heuristic_opt_in_masks_blob() {
        let dlp = DlpEngine::new().with_base64_heuristic(true);
        let (out, count) =
            dlp.sanitize_text("blob QUtJQVhYWFhYWFhYWFhYWFhYWFhYWFhYOndKYWxyWFV0bkZFTUkK end");
        assert_eq!(count, 1);
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }
}
