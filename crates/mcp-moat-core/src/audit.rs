use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AuditLevel {
    #[default]
    Full,
    DecisionsOnly,
    ViolationsOnly,
}

impl std::str::FromStr for AuditLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(AuditLevel::Full),
            "decisions_only" | "decisions" => Ok(AuditLevel::DecisionsOnly),
            "violations_only" | "violations" => Ok(AuditLevel::ViolationsOnly),
            _ => Err(format!(
                "Unknown audit level: '{}'. Expected full, decisions_only, or violations_only",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDirection {
    Inbound,
    Outbound,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Block { reason: String },
    AskOperator { summary: String },
}

impl AuditDecision {
    pub fn is_violation(&self) -> bool {
        matches!(self, AuditDecision::Block { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp: String,
    pub session_id: String,
    pub direction: AuditDirection,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<AuditDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dlp_redactions: Option<usize>,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl AuditEvent {
    /// Computes the cryptographic SHA-256 hash for an event over its canonical content + prev_hash
    #[allow(clippy::too_many_arguments)] // part of the public hashing API; fields are hashed one by one
    pub fn compute_hash(
        sequence: u64,
        timestamp: &str,
        session_id: &str,
        direction: AuditDirection,
        method: &str,
        tool_name: Option<&str>,
        target_path: Option<&str>,
        decision: Option<&AuditDecision>,
        operator_decision: Option<&str>,
        payload_preview: Option<&str>,
        dlp_redactions: Option<usize>,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update((timestamp.len() as u32).to_le_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update((session_id.len() as u32).to_le_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(format!("{:?}", direction).as_bytes());
        hasher.update((method.len() as u32).to_le_bytes());
        hasher.update(method.as_bytes());

        if let Some(t) = tool_name {
            hasher.update([1u8]);
            hasher.update((t.len() as u32).to_le_bytes());
            hasher.update(t.as_bytes());
        } else {
            hasher.update([0u8]);
        }

        if let Some(p) = target_path {
            hasher.update([1u8]);
            hasher.update((p.len() as u32).to_le_bytes());
            hasher.update(p.as_bytes());
        } else {
            hasher.update([0u8]);
        }

        if let Some(d) = decision {
            let d_str = format!("{:?}", d);
            hasher.update([1u8]);
            hasher.update((d_str.len() as u32).to_le_bytes());
            hasher.update(d_str.as_bytes());
        } else {
            hasher.update([0u8]);
        }

        if let Some(o) = operator_decision {
            hasher.update([1u8]);
            hasher.update((o.len() as u32).to_le_bytes());
            hasher.update(o.as_bytes());
        } else {
            hasher.update([0u8]);
        }

        if let Some(pay) = payload_preview {
            hasher.update([1u8]);
            hasher.update((pay.len() as u32).to_le_bytes());
            hasher.update(pay.as_bytes());
        } else {
            hasher.update([0u8]);
        }

        if let Some(r) = dlp_redactions {
            hasher.update([1u8]);
            hasher.update((r as u64).to_le_bytes());
        } else {
            hasher.update([0u8]);
        }

        hasher.update(prev_hash.as_bytes());
        let result = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in result {
            use std::fmt::Write;
            let _ = write!(hex, "{:02x}", byte);
        }
        hex
    }

    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_hash(
            self.sequence,
            &self.timestamp,
            &self.session_id,
            self.direction,
            &self.method,
            self.tool_name.as_deref(),
            self.target_path.as_deref(),
            self.decision.as_ref(),
            self.operator_decision.as_deref(),
            self.payload_preview.as_deref(),
            self.dlp_redactions,
            &self.prev_hash,
        );
        expected == self.entry_hash
    }
}

/// Helper that manages cryptographic sequence numbering and hash chaining for a session
#[derive(Debug, Clone)]
pub struct AuditChain {
    session_id: String,
    next_sequence: u64,
    last_hash: String,
}

impl AuditChain {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            next_sequence: 1,
            last_hash: GENESIS_HASH.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)] // mirrors the audit record fields
    pub fn create_event(
        &mut self,
        timestamp: String,
        direction: AuditDirection,
        method: String,
        tool_name: Option<String>,
        target_path: Option<String>,
        decision: Option<AuditDecision>,
        operator_decision: Option<String>,
        payload_preview: Option<String>,
        dlp_redactions: Option<usize>,
    ) -> AuditEvent {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let prev = self.last_hash.clone();
        let entry_hash = AuditEvent::compute_hash(
            seq,
            &timestamp,
            &self.session_id,
            direction,
            &method,
            tool_name.as_deref(),
            target_path.as_deref(),
            decision.as_ref(),
            operator_decision.as_deref(),
            payload_preview.as_deref(),
            dlp_redactions,
            &prev,
        );

        self.last_hash = entry_hash.clone();

        AuditEvent {
            sequence: seq,
            timestamp,
            session_id: self.session_id.clone(),
            direction,
            method,
            tool_name,
            target_path,
            decision,
            operator_decision,
            payload_preview,
            dlp_redactions,
            prev_hash: prev,
            entry_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub total_records: usize,
    pub is_valid: bool,
    pub tampered_sequence: Option<u64>,
    pub error_message: Option<String>,
}

/// Verifies the cryptographic SHA-256 hash-chain of an audit log stream
pub fn verify_audit_log(
    reader: impl io::BufRead,
) -> Result<VerificationReport, Box<dyn std::error::Error>> {
    let mut sessions: HashMap<String, (u64, String)> = HashMap::new();
    let mut count = 0;

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(trimmed) {
            Ok(ev) => ev,
            Err(e) => {
                return Ok(VerificationReport {
                    total_records: count,
                    is_valid: false,
                    tampered_sequence: None,
                    error_message: Some(format!(
                        "Malformed audit record on line {}: {}",
                        count + 1,
                        e
                    )),
                });
            }
        };
        count += 1;

        match sessions.get_mut(&event.session_id) {
            None => {
                if event.sequence != 1 {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(format!(
                            "Invalid starting sequence: expected sequence 1, found {}",
                            event.sequence
                        )),
                    });
                }

                if event.prev_hash != GENESIS_HASH {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(
                            "Broken genesis hash at sequence 1: genesis hash mismatch".to_string(),
                        ),
                    });
                }

                if !event.verify_hash() {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(format!(
                            "Corrupted entry hash at sequence {}: content does not match hash",
                            event.sequence
                        )),
                    });
                }

                sessions.insert(
                    event.session_id.clone(),
                    (event.sequence, event.entry_hash.clone()),
                );
            }
            Some((last_seq, last_hash)) => {
                if event.sequence != *last_seq + 1 {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(format!(
                            "Broken sequence continuity: expected sequence {}, found {}",
                            *last_seq + 1,
                            event.sequence
                        )),
                    });
                }

                if event.prev_hash != *last_hash {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(format!(
                            "Broken hash chain at sequence {}: previous entry hash mismatch",
                            event.sequence
                        )),
                    });
                }

                if !event.verify_hash() {
                    return Ok(VerificationReport {
                        total_records: count,
                        is_valid: false,
                        tampered_sequence: Some(event.sequence),
                        error_message: Some(format!(
                            "Corrupted entry hash at sequence {}: content does not match hash",
                            event.sequence
                        )),
                    });
                }

                *last_seq = event.sequence;
                *last_hash = event.entry_hash.clone();
            }
        }
    }

    Ok(VerificationReport {
        total_records: count,
        is_valid: true,
        tampered_sequence: None,
        error_message: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_creation_and_verification() {
        let mut chain = AuditChain::new("session-123");

        let e1 = chain.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "initialize".to_string(),
            None,
            None,
            Some(AuditDecision::Allow),
            None,
            None,
            None,
        );

        let e2 = chain.create_event(
            "2026-10-24T00:00:02Z".to_string(),
            AuditDirection::Inbound,
            "tools/call".to_string(),
            Some("write_file".to_string()),
            Some("test.txt".to_string()),
            Some(AuditDecision::Block {
                reason: "Denied".to_string(),
            }),
            None,
            Some("content".to_string()),
            Some(0),
        );

        assert_eq!(e1.sequence, 1);
        assert_eq!(e1.prev_hash, GENESIS_HASH);
        assert_eq!(e2.sequence, 2);
        assert_eq!(e2.prev_hash, e1.entry_hash);

        assert!(e1.verify_hash());
        assert!(e2.verify_hash());

        // Verify log stream
        let log_data = format!(
            "{}\n{}\n",
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap()
        );
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_records, 2);
    }

    #[test]
    fn test_tamper_detection_modified_content() {
        let mut chain = AuditChain::new("session-tamper");
        let mut e1 = chain.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "ping".to_string(),
            None,
            None,
            Some(AuditDecision::Allow),
            None,
            None,
            None,
        );

        // Tamper with event content without updating entry_hash
        e1.method = "tampered_method".to_string();

        let log_data = format!("{}\n", serde_json::to_string(&e1).unwrap());
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.tampered_sequence, Some(1));
    }

    #[test]
    fn test_tamper_detection_deleted_line() {
        let mut chain = AuditChain::new("session-deletion");
        let e1 = chain.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let _e2 = chain.create_event(
            "2026-10-24T00:00:02Z".to_string(),
            AuditDirection::Inbound,
            "ping".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e3 = chain.create_event(
            "2026-10-24T00:00:03Z".to_string(),
            AuditDirection::Inbound,
            "list".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        // Attacker deletes line 2 (e2):
        let log_data = format!(
            "{}\n{}\n",
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e3).unwrap()
        );
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(!report.is_valid);
        assert_eq!(
            report.tampered_sequence,
            Some(3),
            "Chain break must be caught on line 3"
        );
    }

    #[test]
    fn test_multi_session_verification() {
        let mut chain1 = AuditChain::new("session-1");
        let e1_1 = chain1.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e1_2 = chain1.create_event(
            "2026-10-24T00:00:02Z".to_string(),
            AuditDirection::Inbound,
            "ping".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut chain2 = AuditChain::new("session-2");
        let e2_1 = chain2.create_event(
            "2026-10-24T00:01:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e2_2 = chain2.create_event(
            "2026-10-24T00:01:02Z".to_string(),
            AuditDirection::Inbound,
            "tools/list".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let log_data = format!(
            "{}\n{}\n{}\n{}\n",
            serde_json::to_string(&e1_1).unwrap(),
            serde_json::to_string(&e1_2).unwrap(),
            serde_json::to_string(&e2_1).unwrap(),
            serde_json::to_string(&e2_2).unwrap()
        );
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(report.is_valid);
        assert_eq!(report.total_records, 4);
    }

    #[test]
    fn test_canonical_boundary_separation() {
        // Test that shifting string boundaries across tool_name and target_path produces different hashes
        let hash1 = AuditEvent::compute_hash(
            1,
            "2026-10-24T00:00:01Z",
            "sess-1",
            AuditDirection::Inbound,
            "tools/call",
            Some("read_file"),
            Some("/etc/shadow"),
            None,
            None,
            None,
            None,
            GENESIS_HASH,
        );

        let hash2 = AuditEvent::compute_hash(
            1,
            "2026-10-24T00:00:01Z",
            "sess-1",
            AuditDirection::Inbound,
            "tools/call",
            Some("read_file/etc/shadow"),
            None,
            None,
            None,
            None,
            None,
            GENESIS_HASH,
        );

        assert_ne!(
            hash1, hash2,
            "Canonical length prefixing must prevent field boundary collision"
        );
    }

    #[test]
    fn test_canonical_decision_vs_operator_decision() {
        let block_decision = AuditDecision::Block {
            reason: "Access denied".to_string(),
        };

        // Event A: Decision = Block, operator_decision = None
        let hash_a = AuditEvent::compute_hash(
            1,
            "2026-10-24T00:00:01Z",
            "sess-1",
            AuditDirection::Inbound,
            "tools/call",
            Some("write_file"),
            None,
            Some(&block_decision),
            None,
            None,
            None,
            GENESIS_HASH,
        );

        // Event B: Decision = None, operator_decision = formatted string of Block
        let d_str = format!("{:?}", block_decision);
        let hash_b = AuditEvent::compute_hash(
            1,
            "2026-10-24T00:00:01Z",
            "sess-1",
            AuditDirection::Inbound,
            "tools/call",
            Some("write_file"),
            None,
            None,
            Some(&d_str),
            None,
            None,
            GENESIS_HASH,
        );

        assert_ne!(
            hash_a, hash_b,
            "Domain tags must prevent decision vs operator_decision collision"
        );
    }

    #[test]
    fn test_interleaved_multi_session_verification() {
        let mut chain1 = AuditChain::new("session-A");
        let e1_1 = chain1.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e1_2 = chain1.create_event(
            "2026-10-24T00:00:03Z".to_string(),
            AuditDirection::Inbound,
            "ping".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let mut chain2 = AuditChain::new("session-B");
        let e2_1 = chain2.create_event(
            "2026-10-24T00:00:02Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e2_2 = chain2.create_event(
            "2026-10-24T00:00:04Z".to_string(),
            AuditDirection::Inbound,
            "tools/list".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        // Interleaved: A1, B1, A2, B2
        let log_data = format!(
            "{}\n{}\n{}\n{}\n",
            serde_json::to_string(&e1_1).unwrap(),
            serde_json::to_string(&e2_1).unwrap(),
            serde_json::to_string(&e1_2).unwrap(),
            serde_json::to_string(&e2_2).unwrap()
        );
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(
            report.is_valid,
            "Interleaved sessions must verify successfully via per-session state tracking"
        );
        assert_eq!(report.total_records, 4);
    }

    #[test]
    fn test_session_starting_sequence_must_be_one() {
        let mut chain = AuditChain::new("session-invalid-start");
        let _e1 = chain.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let e2 = chain.create_event(
            "2026-10-24T00:00:02Z".to_string(),
            AuditDirection::Inbound,
            "ping".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        // Start log file with e2 (sequence = 2), omitting sequence 1
        let log_data = format!("{}\n", serde_json::to_string(&e2).unwrap());
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.tampered_sequence, Some(2));
        assert!(report
            .error_message
            .unwrap()
            .contains("Invalid starting sequence"));
    }

    #[test]
    fn test_tamper_detection_malformed_json_record() {
        let mut chain = AuditChain::new("session-malformed");
        let e1 = chain.create_event(
            "2026-10-24T00:00:01Z".to_string(),
            AuditDirection::Inbound,
            "init".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let log_data = format!(
            "{}\n{{not valid json}}\n",
            serde_json::to_string(&e1).unwrap()
        );
        let report = verify_audit_log(log_data.as_bytes()).unwrap();
        assert!(!report.is_valid);
        assert!(report
            .error_message
            .unwrap()
            .contains("Malformed audit record on line 2"));
    }
}
