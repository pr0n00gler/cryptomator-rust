use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// HTTP Basic-Auth credential checker.
///
/// The stored expected header value is kept in a `Zeroizing` wrapper so the
/// credential bytes are wiped from memory when the struct is dropped.
#[derive(Clone)]
pub struct WebDavAuth {
    /// `"Basic <base64(user:pass)>"` — kept zeroized to wipe the credential
    /// from memory when dropped.
    expected_header_value: Arc<Zeroizing<String>>,
}

impl WebDavAuth {
    pub fn new(user: &str, pass: &str) -> Self {
        // Every intermediate string is wrapped in `Zeroizing` so the plaintext
        // credential bytes and their base64 representation are deterministically
        // wiped from the heap when each binding goes out of scope.
        //
        // Without this, `credentials` ("user:pass") and `b64` would remain on
        // the heap until the allocator happened to overwrite them — potentially
        // never within the process lifetime — creating a key-in-memory exposure
        // window for any process-memory scanner or crash dump.
        let credentials = Zeroizing::new(format!("{user}:{pass}"));
        let b64 = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        let header_value = Zeroizing::new(format!("Basic {}", b64.as_str()));
        Self {
            expected_header_value: Arc::new(header_value),
        }
    }

    /// Returns `true` if `auth_header` exactly matches the expected
    /// `"Basic <base64>"` value.
    ///
    /// The comparison is *constant-time
    pub fn check(&self, auth_header: &str) -> bool {
        // We use constant time comparison to prevent timing attacks.
        // If lengths differ, they are definitely not equal, but we still
        // want to avoid leaking information about the expected value.
        use subtle::ConstantTimeEq;

        let expected = self.expected_header_value.as_bytes();
        let actual = auth_header.as_bytes();

        if expected.len() != actual.len() {
            // Still do a dummy comparison to maintain similar timing profile
            // although for different lengths the early exit of logical != is usually acceptable
            // unless we want to be extremely paranoid.
            // Using a dummy comparison against itself to be safe.
            let _ = expected.ct_eq(expected);
            return false;
        }

        expected.ct_eq(actual).into()
    }
}

impl fmt::Display for WebDavAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebDavAuth(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_check_correct_credential() {
        let auth = WebDavAuth::new("user", "pass");
        // echo -n "user:pass" | base64 -> dXNlcjpwYXNz
        assert!(auth.check("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_auth_check_wrong_password() {
        let auth = WebDavAuth::new("user", "pass");
        assert!(!auth.check("Basic dXNlcjp3cm9uZw=="));
    }

    #[test]
    fn test_auth_check_shorter_header() {
        let auth = WebDavAuth::new("user", "pass");
        assert!(!auth.check("Basic dXNlcjpwYXN")); // shorter
    }

    #[test]
    fn test_auth_check_longer_header() {
        let auth = WebDavAuth::new("user", "pass");
        assert!(!auth.check("Basic dXNlcjpwYXNzcw==")); // longer
    }

    #[test]
    fn test_auth_check_wrong_scheme() {
        let auth = WebDavAuth::new("user", "pass");
        assert!(!auth.check("Bearer header"));
    }

    #[test]
    fn test_auth_check_empty_header() {
        let auth = WebDavAuth::new("user", "pass");
        assert!(!auth.check(""));
    }

    #[test]
    fn test_auth_display_does_not_expose_credential() {
        let auth = WebDavAuth::new("secret_user", "secret_pass");
        let display_str = format!("{auth}");
        assert!(!display_str.contains("secret_user"));
        assert!(!display_str.contains("secret_pass"));
    }

    #[test]
    fn test_auth_check_special_characters() {
        let auth = WebDavAuth::new("user@domain.com", "p@$$w0rd!");
        let credentials = base64::engine::general_purpose::STANDARD
            .encode("user@domain.com:p@$$w0rd!".as_bytes());
        let header = format!("Basic {credentials}");
        assert!(auth.check(&header));
    }
}
