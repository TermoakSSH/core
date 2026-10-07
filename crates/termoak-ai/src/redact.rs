//! Secret redaction before anything goes to an AI provider.
//!
//! Tool outputs (command output, file contents, terminal screens) and the
//! terminal context of the quick assistant pass through [`redact`] before
//! the model sees them. It replaces with `[redacted]`:
//!
//! - private key blocks (`-----BEGIN … PRIVATE KEY-----` … `-----END …-----`,
//!   also with escaped `\n` as in JSON service-account files);
//! - `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Cookie` and
//!   `Set-Cookie` header values;
//! - the password of `scheme://user:password@host` URLs;
//! - values of secret-looking keys: `password=…`, `DB_PASSWORD=…`,
//!   `"api_key": "…"`, `export GITHUB_TOKEN=…`, `client_secret: …`,
//!   `--password …` (`.env` files, YAML, JSON, INI, command lines…);
//! - well-known token formats: AWS access key ids (`AKIA…`, `ASIA…`), Google
//!   API keys (`AIza…`) and OAuth tokens (`ya29.…`), GitHub (`ghp_…`,
//!   `github_pat_…`), GitLab (`glpat-…`), Slack (`xox?-…`), Stripe
//!   (`sk_live_…`), OpenAI/Anthropic (`sk-…`), npm (`npm_…`), Hugging Face
//!   (`hf_…`) and JWTs (`eyJ….eyJ….…`).
//!
//! It is a heuristic: it prefers hiding a harmless value to leaking a
//! secret, and keeps the key names so the model still understands the file.
//! Values that are clearly not secrets (empty, `true`/`false`, `yes`/`no`,
//! variable references such as `${DB_PASS}`, placeholders such as
//! `<password>` or `****`) are kept.

/// What replaces a secret.
pub const REDACTED: &str = "[redacted]";

/// Hides the secrets in `text` (see the module docs).
pub fn redact(text: &str) -> String {
    let text = redact_private_keys(text);
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        out.push_str(&redact_line(line));
    }
    out
}

/// Hides the secrets inside the `<context>` blocks that clients put before
/// a request (the terminal screen...), leaving the user's own words as they
/// are.
pub fn redact_context_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<context>") {
        let Some(len) = rest[start..].find("</context>") else {
            break;
        };
        let end = start + len + "</context>".len();
        out.push_str(&rest[..start]);
        out.push_str(&redact(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Did [`redact`] hide anything?
pub fn contains_secrets(text: &str) -> bool {
    redact(text) != text
}

// --- Private key blocks ------------------------------------------------------

fn redact_private_keys(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after_begin = &rest[start + "-----BEGIN ".len()..];
        let Some(label_end) = after_begin.find("-----") else {
            break;
        };
        let label = &after_begin[..label_end];
        if !label.contains("PRIVATE KEY") || label.len() > 60 {
            out.push_str(&rest[..start + "-----BEGIN ".len()]);
            rest = after_begin;
            continue;
        }
        let header_len = start + "-----BEGIN ".len() + label_end + "-----".len();
        out.push_str(&rest[..header_len]);
        let body = &rest[header_len..];
        match body.find("-----END ") {
            Some(end) => {
                // Keep the separator (real or escaped newline) around the body.
                let (lead, trail) = (newline_prefix(body), newline_suffix(&body[..end]));
                out.push_str(lead);
                out.push_str(REDACTED);
                out.push_str(trail);
                rest = &body[end..];
            }
            None => {
                // Cut off (truncated output): hide everything after the header.
                out.push_str(newline_prefix(body));
                out.push_str(REDACTED);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

fn newline_prefix(s: &str) -> &str {
    for p in ["\r\n", "\n", "\\n"] {
        if s.starts_with(p) {
            return p;
        }
    }
    ""
}

fn newline_suffix(s: &str) -> &str {
    for p in ["\r\n", "\n", "\\n"] {
        if s.ends_with(p) {
            return p;
        }
    }
    ""
}

// --- One line ------------------------------------------------------------------

fn redact_line(line: &str) -> String {
    let line = redact_headers(line);
    let line = redact_url_passwords(&line);
    let line = redact_key_values(&line);
    let line = redact_flag_values(&line);
    redact_tokens(&line)
}

/// `Authorization: Bearer …` and friends (also inside `curl -H '…'`).
fn redact_headers(line: &str) -> String {
    const HEADERS: &[&str] = &[
        "proxy-authorization",
        "authorization",
        "x-api-key",
        "x-auth-token",
        "set-cookie",
        "cookie",
    ];
    let lower = line.to_ascii_lowercase();
    let mut out = String::new();
    let mut pos = 0;
    while pos < line.len() {
        let found = HEADERS
            .iter()
            .filter_map(|h| {
                lower[pos..]
                    .find(&format!("{h}:"))
                    .map(|i| (pos + i, h.len()))
            })
            .min_by_key(|(i, _)| *i);
        let Some((at, len)) = found else { break };
        // A word on its own (not `x-authorization:` or `my_cookie:`).
        let before = line[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            out.push_str(&line[pos..at + len + 1]);
            pos = at + len + 1;
            continue;
        }
        let value_start = at + len + 1;
        let quote = before.filter(|c| *c == '"' || *c == '\'');
        let rest = &line[value_start..];
        let value_len = match quote {
            Some(q) => rest
                .find(q)
                .unwrap_or(rest.trim_end_matches(['\r', '\n']).len()),
            None => rest.trim_end_matches(['\r', '\n']).len(),
        };
        let value = &rest[..value_len];
        out.push_str(&line[pos..value_start]);
        if value.trim().is_empty() || value.trim() == REDACTED {
            out.push_str(value);
        } else {
            out.push(' ');
            out.push_str(REDACTED);
        }
        pos = value_start + value_len;
    }
    out.push_str(&line[pos..]);
    out
}

/// `scheme://user:password@host` → `scheme://user:[redacted]@host`.
fn redact_url_passwords(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | '?' | '#'))
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                match userinfo.find(':') {
                    Some(colon)
                        if colon + 1 < userinfo.len() && &userinfo[colon + 1..] != REDACTED =>
                    {
                        out.push_str(&userinfo[..colon + 1]);
                        out.push_str(REDACTED);
                        out.push_str(&authority[at..]);
                    }
                    _ => out.push_str(authority),
                }
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Words of a key name: `DB_PASSWORD` → `db password`, `apiKey` → `api key`.
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Does a key (`DB_PASSWORD`, `apiKey`, `client-secret`…) name a secret?
pub fn is_secret_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 80 {
        return false;
    }
    let words = key_words(key);
    let has = |w: &str| words.iter().any(|x| x == w);
    // Settings about secrets, not secrets (`PasswordAuthentication`,
    // `password_file`, `token_ttl`, `PASS_MAX_DAYS`…).
    const NOT_SECRET: &[&str] = &[
        "authentication",
        "file",
        "path",
        "dir",
        "length",
        "len",
        "min",
        "max",
        "days",
        "policy",
        "expiry",
        "expires",
        "expiration",
        "ttl",
        "timeout",
        "type",
        "prompt",
        "reset",
        "required",
        "changed",
        "change",
        "age",
        "warn",
        "inactive",
        "lifetime",
        "count",
        "enabled",
        "mode",
        "method",
        "helper",
        "command",
        "cmd",
        "url",
        "endpoint",
        "name",
        "id",
        "usage",
        "env",
    ];
    if NOT_SECRET.iter().any(|w| has(w)) {
        return false;
    }
    const SECRET: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "credential",
        "credentials",
        "authtoken",
        "privatekey",
        "accesskey",
        "secretkey",
    ];
    // `PWD` / `OLDPWD` in `env` output are directories.
    if key == "PWD" {
        return false;
    }
    if SECRET.iter().any(|w| has(w)) {
        return true;
    }
    has("key")
        && [
            "api",
            "access",
            "private",
            "secret",
            "signing",
            "encryption",
            "master",
            "auth",
            "license",
            "app",
        ]
        .iter()
        .any(|w| has(w))
}

/// Values that are not secrets and are kept.
fn is_harmless_value(v: &str) -> bool {
    let t = v.trim();
    let l = t.to_ascii_lowercase();
    t.is_empty()
        || t == REDACTED
        || t.starts_with('$')
        || t.starts_with("%(")
        || t.starts_with('<')
        || (t.starts_with("{{") && t.ends_with("}}"))
        || t.chars()
            .all(|c| c == '*' || c == 'x' || c == 'X' || c == '•')
        || matches!(
            l.as_str(),
            "true"
                | "false"
                | "yes"
                | "no"
                | "null"
                | "none"
                | "nil"
                | "on"
                | "off"
                | "0"
                | "1"
                | "''"
                | "\"\""
        )
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// `key=value`, `key: value`, `"key": "value"`, `KEY = 'value'`.
fn redact_key_values(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let sep = bytes[i];
        if sep != b'=' && sep != b':' {
            i += 1;
            continue;
        }
        // `==`, `:=`, `://`, `::` are not assignments.
        if bytes
            .get(i + 1)
            .is_some_and(|b| *b == b'=' || *b == b'/' || *b == b':')
            || (i > 0 && matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>' | b':'))
        {
            i += 1;
            continue;
        }
        // The key before the separator (optionally quoted, with spaces).
        let mut k_end = i;
        while k_end > 0 && bytes[k_end - 1] == b' ' {
            k_end -= 1;
        }
        let quoted_key = k_end > 0 && matches!(bytes[k_end - 1], b'"' | b'\'');
        if quoted_key {
            k_end -= 1;
        }
        let mut k_start = k_end;
        while k_start > 0 && is_key_char(bytes[k_start - 1] as char) {
            k_start -= 1;
        }
        let key = line[k_start..k_end].trim_start_matches('-');
        if !is_secret_key(key) {
            i += 1;
            continue;
        }
        // The value after it.
        let mut v_start = i + 1;
        while v_start < bytes.len() && bytes[v_start] == b' ' {
            v_start += 1;
        }
        if v_start >= bytes.len() {
            break;
        }
        let (inner_start, inner_end, next) = match bytes[v_start] {
            q @ (b'"' | b'\'') => {
                let close = line[v_start + 1..]
                    .find(q as char)
                    .map(|p| v_start + 1 + p)
                    .unwrap_or(line.trim_end_matches(['\r', '\n']).len());
                (v_start + 1, close, close)
            }
            _ => {
                let end = line[v_start..]
                    .find(|c: char| {
                        c.is_whitespace()
                            || matches!(c, '&' | ',' | ';' | '"' | '\'' | '}' | ')' | ']')
                    })
                    .map(|p| v_start + p)
                    .unwrap_or(line.len());
                (v_start, end, end)
            }
        };
        let inner_end = inner_end.max(inner_start);
        let value = &line[inner_start..inner_end];
        // `password:` at the end of a YAML key with a nested block, `key: {`…
        if is_harmless_value(value) || value.starts_with('{') || value.starts_with('[') {
            i = next.max(i + 1);
            continue;
        }
        out.push_str(&line[copied..inner_start]);
        out.push_str(REDACTED);
        copied = inner_end;
        i = next.max(i + 1);
    }
    out.push_str(&line[copied..]);
    out
}

/// `--password secret`, `--api-key "x y"` (the value as the next word).
fn redact_flag_values(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(p) = line[search..].find("--") {
        let at = search + p;
        search = at + 2;
        if at > 0 && !line[..at].ends_with([' ', '\t', '"', '\'']) {
            continue;
        }
        let name_end = line[at + 2..]
            .find(|c: char| !is_key_char(c))
            .map(|q| at + 2 + q)
            .unwrap_or(line.len());
        let name = &line[at + 2..name_end];
        if !is_secret_key(name) || !line[name_end..].starts_with(' ') {
            continue;
        }
        let v_start = name_end + line[name_end..].len() - line[name_end..].trim_start().len();
        if v_start >= line.len() || line[v_start..].starts_with('-') {
            continue;
        }
        let (inner_start, inner_end) = match line.as_bytes()[v_start] {
            q @ (b'"' | b'\'') => {
                let close = line[v_start + 1..]
                    .find(q as char)
                    .map(|c| v_start + 1 + c)
                    .unwrap_or(line.trim_end().len());
                (v_start + 1, close.max(v_start + 1))
            }
            _ => (
                v_start,
                line[v_start..]
                    .find(char::is_whitespace)
                    .map(|c| v_start + c)
                    .unwrap_or(line.len()),
            ),
        };
        let value = &line[inner_start..inner_end];
        if is_harmless_value(value) {
            continue;
        }
        out.push_str(&line[copied..inner_start]);
        out.push_str(REDACTED);
        copied = inner_end;
        search = inner_end;
    }
    out.push_str(&line[copied..]);
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=')
}

/// Well-known token formats (see the module docs).
fn looks_like_token(w: &str) -> bool {
    let alnum = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric());
    let len = w.len();
    let upper_alnum = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    };
    // AWS access key ids.
    if len == 20
        && ["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA"]
            .iter()
            .any(|p| w.starts_with(p))
        && upper_alnum(w)
    {
        return true;
    }
    // Google API keys and OAuth access tokens.
    if w.starts_with("AIza") && len == 39 {
        return true;
    }
    if w.starts_with("ya29.") && len > 30 {
        return true;
    }
    let prefixed = |p: &str, min: usize| w.starts_with(p) && len >= p.len() + min;
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|p| prefixed(p, 30) && alnum(&w[p.len()..]))
        || prefixed("github_pat_", 30)
        || prefixed("glpat-", 20)
        || prefixed("npm_", 30)
        || prefixed("hf_", 30) && alnum(&w[3..])
        || ["sk_live_", "rk_live_", "sk_test_", "rk_test_"]
            .iter()
            .any(|p| prefixed(p, 16))
        || prefixed("sk-", 20) && w[3..].chars().any(|c| c.is_ascii_digit())
        || ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"]
            .iter()
            .any(|p| prefixed(p, 10))
    {
        return true;
    }
    // JWT: three base64url parts, the first two JSON objects.
    if w.starts_with("eyJ") && len > 30 {
        let parts: Vec<&str> = w.split('.').collect();
        if parts.len() == 3 && parts[1].starts_with("eyJ") && parts.iter().all(|p| !p.is_empty()) {
            return true;
        }
    }
    false
}

fn redact_tokens(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut i = 0;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        if !is_token_char(bytes[i] as char) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_token_char(bytes[i] as char) {
            i += 1;
        }
        let word = line[start..i].trim_end_matches(['.', ',', '=']);
        if looks_like_token(word) {
            out.push_str(&line[copied..start]);
            out.push_str(REDACTED);
            copied = start + word.len();
        }
    }
    out.push_str(&line[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hidden(input: &str, secret: &str) {
        let out = redact(input);
        assert!(!out.contains(secret), "{secret} leaked in: {out}");
        assert!(out.contains(REDACTED), "nothing redacted in: {out}");
    }

    fn kept(input: &str) {
        assert_eq!(redact(input), input);
    }

    #[test]
    fn key_values() {
        hidden("password=hunter2", "hunter2");
        hidden("DB_PASSWORD=s3cr3t!\nDB_HOST=db1\n", "s3cr3t!");
        hidden("export GITHUB_TOKEN=abc123def", "abc123def");
        hidden("  client_secret: 'very secret'", "very secret");
        hidden(r#"{"api_key": "k-123456", "user": "bob"}"#, "k-123456");
        hidden("apiKey = \"zzz-111\"", "zzz-111");
        hidden("https://x.com/cb?user=a&access_token=tok999&x=1", "tok999");
        hidden("mysql.secret_key_base: 0123abcd", "0123abcd");
        hidden(
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
            "wJalrXUtnFEMI",
        );
        let out = redact("DB_PASSWORD=s3cr3t DB_HOST=db1");
        assert_eq!(out, "DB_PASSWORD=[redacted] DB_HOST=db1");
        let out = redact(r#"{"password": "a b c", "user": "bob"}"#);
        assert_eq!(out, r#"{"password": "[redacted]", "user": "bob"}"#);
    }

    #[test]
    fn harmless_values_and_settings_are_kept() {
        kept("PasswordAuthentication: yes");
        kept("PasswordAuthentication no");
        kept("password_file=/etc/app/pass.txt");
        kept("PASS_MAX_DAYS 99999");
        kept("token_ttl=3600");
        kept("DB_PASSWORD=${DB_PASSWORD}");
        kept("password: <your password>");
        kept("password=");
        kept("PWD=/home/bob");
        kept("password: ****");
        kept("ls -la /etc/passwd");
        kept("if a == b: pass");
        kept("http://example.com:8080/path");
        kept("2024-01-01 12:30:45 nginx: started");
        kept("Authorization:");
    }

    #[test]
    fn headers() {
        hidden("Authorization: Bearer eyabc.def", "eyabc");
        hidden(
            "curl -H 'Authorization: Basic dXNlcjpwYXNz' https://x",
            "dXNlcjpwYXNz",
        );
        let out = redact("curl -H \"X-Api-Key: 1234\" -d x https://a");
        assert_eq!(out, "curl -H \"X-Api-Key: [redacted]\" -d x https://a");
        hidden("Cookie: session=abcdef; theme=dark", "abcdef");
        hidden("< Set-Cookie: sid=999; HttpOnly", "999");
    }

    #[test]
    fn url_passwords() {
        assert_eq!(
            redact("DATABASE_URL_X postgres://app:pw123@db:5432/app"),
            "DATABASE_URL_X postgres://app:[redacted]@db:5432/app"
        );
        kept("ssh://git@github.com/x/y");
    }

    #[test]
    fn flags() {
        assert_eq!(
            redact("mysqldump --password s3cret --user root db"),
            "mysqldump --password [redacted] --user root db"
        );
        hidden("tool --api-key \"a b\" run", "a b");
        hidden("tool --token=abc run", "abc");
        kept("tool --password-file /run/secret");
        kept("tool --token --verbose");
    }

    #[test]
    fn private_keys() {
        let pem = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter\n";
        let out = redact(pem);
        assert_eq!(
            out,
            "before\n-----BEGIN OPENSSH PRIVATE KEY-----\n[redacted]\n-----END OPENSSH PRIVATE KEY-----\nafter\n"
        );
        // JSON service account with escaped newlines.
        let json = r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n", "client_email": "a@b.iam.gserviceaccount.com"}"#;
        let out = redact(json);
        assert!(!out.contains("MIIEvQIBADANBg"), "{out}");
        assert!(out.contains("client_email"));
        // Truncated output: everything after the header.
        hidden("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\nMIIdef", "MIIabc");
        // Public keys and certificates are kept.
        kept("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        kept("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n");
    }

    #[test]
    fn tokens() {
        hidden("key id AKIAIOSFODNN7EXAMPLE in use", "AKIAIOSFODNN7EXAMPLE");
        hidden("google: AIzaSyA-1234567890abcdefghijklmnopqrstu", "AIzaSyA");
        hidden(
            "remote: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghp_abc",
        );
        hidden("glpat-abcdefghij0123456789", "glpat-abc");
        hidden("xoxb-123456789012-abcdef", "xoxb-123");
        hidden("OPENAI sk-proj-abc123def456ghi789jkl", "sk-proj");
        hidden("sk_live_abcdefghijklmnop1234", "sk_live_");
        hidden(
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "eyJzdWIi",
        );
        kept("commit 4f2a9c1b and sk-learn tutorial");
        kept("task-runner-1234 eyJ");
    }

    #[test]
    fn multi_line_output_keeps_its_shape() {
        let env = "APP_ENV=production\nAPP_KEY=base64:QUJDREVGR0g=\nDB_USERNAME=app\nDB_PASSWORD=pa55\nMAIL_PORT=587\n";
        let out = redact(env);
        assert_eq!(
            out,
            "APP_ENV=production\nAPP_KEY=[redacted]\nDB_USERNAME=app\nDB_PASSWORD=[redacted]\nMAIL_PORT=587\n"
        );
        assert_eq!(out.lines().count(), env.lines().count());
        assert!(contains_secrets(env));
        assert!(!contains_secrets("nothing to see"));
    }

    #[test]
    fn only_context_blocks_of_a_request() {
        let req = "<context>\nscreen: password=abc\n</context>\n\nmy password=keepme is wrong?";
        assert_eq!(
            redact_context_blocks(req),
            "<context>\nscreen: password=[redacted]\n</context>\n\nmy password=keepme is wrong?"
        );
        assert_eq!(redact_context_blocks("no context"), "no context");
    }

    #[test]
    fn key_names() {
        for k in [
            "password",
            "DB_PASSWORD",
            "apiKey",
            "api-key",
            "client_secret",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "private_key",
            "PRIVATE_KEY",
            "passphrase",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in [
            "PasswordAuthentication",
            "user",
            "key",
            "host",
            "password_file",
            "keyboard",
            "token_type",
        ] {
            assert!(!is_secret_key(k), "{k}");
        }
    }
}
