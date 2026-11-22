use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Simple structured admin audit entry used for admin operations (cache flush,
/// kill-switch changes, etc.). Written as JSON to stdout by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEntry {
    pub event: String,
    pub request_id: String,
    pub actor: String,
    pub resource: String,
    pub outcome: String,
    pub timestamp: DateTime<Utc>,
}

/// Build an `AdminAuditEntry` with redacted actor information.
pub fn build_admin_audit_entry(
    event: impl Into<String>,
    request_id: impl Into<String>,
    headers: &HeaderMap,
    client_ip: IpAddr,
    resource: impl Into<String>,
    outcome: impl Into<String>,
) -> AdminAuditEntry {
    let actor_raw = extract_actor(headers, client_ip);
    let actor = redact_actor(&actor_raw);

    AdminAuditEntry {
        event: event.into(),
        request_id: request_id.into(),
        actor,
        resource: resource.into(),
        outcome: outcome.into(),
        timestamp: Utc::now(),
    }
}

/// Emit the audit entry as JSON to stdout when `ADMIN_AUDIT_ENABLED` is not set
/// to "false"/"0". Returns the serialized JSON string on success.
pub fn emit_admin_audit(entry: &AdminAuditEntry) -> Option<String> {
    let enabled = std::env::var("ADMIN_AUDIT_ENABLED")
        .map(|v| !v.eq_ignore_ascii_case("false") && v != "0")
        .unwrap_or(true);

    let json = match serde_json::to_string(entry) {
        Ok(j) => j,
        Err(_) => return None,
    };

    if enabled {
        println!("{}", json);
    }

    Some(json)
}

/// Redact actor secrets. Expected input formats:
/// - "apikey:actual-secret" => "apikey:[REDACTED]"
/// - "token:the-token" => "token:[REDACTED]"
/// - "ip:1.2.3.4" => unchanged
fn redact_actor(actor: &str) -> String {
    if actor.starts_with("apikey:") {
        "apikey:[REDACTED]".to_string()
    } else if actor.starts_with("token:") {
        "token:[REDACTED]".to_string()
    } else {
        actor.to_string()
    }
}

/// Extract an actor string from common auth headers, falling back to the
/// caller IP that was already resolved through the trusted-proxy boundary.
/// Forwarding headers are never read directly here: they are only trustworthy
/// when the TCP peer is a configured trusted proxy.
fn extract_actor(headers: &HeaderMap, client_ip: IpAddr) -> String {
    // X-API-Key
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return format!("apikey:{}", key);
    }

    // Authorization: Bearer token
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = auth.strip_prefix("Bearer ") {
            return format!("token:{}", tok);
        }
    }

    format!("ip:{client_ip}")
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    fn client_ip(raw: &str) -> IpAddr {
        raw.parse().expect("valid IP")
    }

    #[test]
    fn redact_apikey_and_token() {
        let mut hm = HeaderMap::new();
        hm.insert("x-api-key", "secret-key-123".parse().unwrap());
        let entry = build_admin_audit_entry(
            "cache.flush",
            "req-1",
            &hm,
            client_ip("192.0.2.10"),
            "pairs",
            "success",
        );
        assert_eq!(entry.actor, "apikey:[REDACTED]");

        let mut hm2 = HeaderMap::new();
        hm2.insert("authorization", "Bearer mytoken".parse().unwrap());
        let entry2 = build_admin_audit_entry(
            "ks.update",
            "req-2",
            &hm2,
            client_ip("192.0.2.10"),
            "kill_switch",
            "denied",
        );
        assert_eq!(entry2.actor, "token:[REDACTED]");
    }

    #[test]
    fn json_emitted_when_enabled() {
        std::env::remove_var("ADMIN_AUDIT_ENABLED");
        let hm = HeaderMap::new();
        let entry = build_admin_audit_entry(
            "cache.flush",
            "req-3",
            &hm,
            client_ip("192.0.2.10"),
            "pairs",
            "success",
        );
        let json = emit_admin_audit(&entry).expect("json");
        assert!(json.contains("\"event\":\"cache.flush\""));
        assert!(json.contains("\"request_id\":\"req-3\""));
    }

    #[test]
    fn kill_switch_update_audit_entry_emits_on_success() {
        // Mirrors the entry built by routes::kill_switch::update_kill_switch
        // on a successful update (issue #1053: audit log must still fire).
        std::env::remove_var("ADMIN_AUDIT_ENABLED");
        let mut hm = HeaderMap::new();
        hm.insert("authorization", "Bearer test-admin-token".parse().unwrap());
        let entry = build_admin_audit_entry(
            "kill_switch.update",
            "req-ks-1",
            &hm,
            client_ip("192.0.2.10"),
            "kill_switch",
            "success",
        );
        let json = emit_admin_audit(&entry).expect("kill switch audit entry must emit");
        assert!(json.contains("\"event\":\"kill_switch.update\""));
        assert!(json.contains("\"outcome\":\"success\""));
        // The admin token itself must never be leaked into the audit log.
        assert!(!json.contains("test-admin-token"));
    }

    #[test]
    fn actor_uses_resolved_client_ip_not_forwarding_headers() {
        let mut hm = HeaderMap::new();
        hm.insert("x-forwarded-for", "10.0.0.1, 1.2.3.4".parse().unwrap());
        // The resolver has already decided the caller is 198.51.100.7 (the
        // TCP peer of an untrusted request), so the audit entry must not pick
        // a spoofable header value back up.
        let entry = build_admin_audit_entry(
            "cache.flush",
            "req-4",
            &hm,
            client_ip("198.51.100.7"),
            "all",
            "success",
        );
        assert_eq!(entry.actor, "ip:198.51.100.7");
    }
}
