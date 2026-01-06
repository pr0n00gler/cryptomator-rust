use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct WebDavAuth {
    expected_header_value: Arc<String>,
}

impl WebDavAuth {
    pub fn new(user: &str, pass: &str) -> Self {
        let credentials = format!("{}:{}", user, pass);
        let b64 = STANDARD.encode(credentials);
        Self {
            expected_header_value: Arc::new(format!("Basic {}", b64)),
        }
    }

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
    fn test_auth_check() {
        let auth = WebDavAuth::new("user", "pass");
        // echo -n "user:pass" | base64 -> dXNlcjpwYXNz
        assert!(auth.check("Basic dXNlcjpwYXNz"));
        assert!(!auth.check("Basic dXNlcjp3cm9uZw=="));
        assert!(!auth.check("Basic dXNlcjpwYXN")); // shorter
        assert!(!auth.check("Basic dXNlcjpwYXNzcw==")); // longer
        assert!(!auth.check("Bearer header"));
    }
}
