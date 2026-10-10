use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;

type HmacSha256 = Hmac<Sha256>;

/// Sign a webhook payload with HMAC-SHA256, hex-encoded, for the
/// `X-Kobo-Signature` header. Receivers verify by recomputing this over the
/// raw request body with the shared secret.
pub fn sign_payload(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UrlSafetyError {
    #[error("only http(s) URLs are allowed")]
    BadScheme,
    #[error("URL has no host")]
    NoHost,
    #[error("loopback, private, or link-local targets are not allowed")]
    UnsafeTarget,
}

/// Reject webhook URLs that point at loopback/private/link-local targets,
/// for both IPv4 and bracketed IPv6 — the SSRF guard octo also implements.
/// This only catches literal IP hosts; DNS-based rebinding still needs to be
/// checked at connect time in the HTTP client (documented in SECURITY.md).
///
/// Deliberately dependency-free: a minimal scheme/host split rather than a
/// full URL parser, since this function only ever needs those two pieces.
pub fn is_safe_url(raw: &str) -> Result<(), UrlSafetyError> {
    let (scheme, rest) = raw.split_once("://").ok_or(UrlSafetyError::BadScheme)?;
    if scheme != "http" && scheme != "https" {
        return Err(UrlSafetyError::BadScheme);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(UrlSafetyError::NoHost);
    }
    // Strip userinfo (user:pass@) and port, keep bracketed IPv6 intact.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(bracket_end) = authority.strip_prefix('[').and_then(|s| s.find(']')) {
        &authority[1..bracket_end + 1]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        return Err(UrlSafetyError::NoHost);
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        let unsafe_ip = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
        if unsafe_ip {
            return Err(UrlSafetyError::UnsafeTarget);
        }
    }
    if host == "localhost" {
        return Err(UrlSafetyError::UnsafeTarget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_deterministic() {
        let secret = b"shh";
        let payload = br#"{"event":"deposit"}"#;
        assert_eq!(sign_payload(secret, payload), sign_payload(secret, payload));
    }

    #[test]
    fn rejects_loopback() {
        assert_eq!(is_safe_url("http://127.0.0.1/hook"), Err(UrlSafetyError::UnsafeTarget));
        assert_eq!(is_safe_url("http://localhost/hook"), Err(UrlSafetyError::UnsafeTarget));
    }

    #[test]
    fn rejects_private_ranges() {
        assert_eq!(is_safe_url("http://10.0.0.5/hook"), Err(UrlSafetyError::UnsafeTarget));
        assert_eq!(is_safe_url("http://192.168.1.5/hook"), Err(UrlSafetyError::UnsafeTarget));
    }

    #[test]
    fn accepts_public_https() {
        assert!(is_safe_url("https://your.app/hooks").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert_eq!(is_safe_url("file:///etc/passwd"), Err(UrlSafetyError::BadScheme));
    }
}
