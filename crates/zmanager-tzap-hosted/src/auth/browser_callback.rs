//! One bounded parser for browser callbacks delivered by loopback or manually.

use crate::auth_client::{TzapAuthError, validate_oauth_state};

pub const MAX_CALLBACK_URL_BYTES: usize = 8192;

/// The browser carries only an opaque state and a one-time exchange code.
/// Deliberately does not implement Debug: the code must not enter diagnostics.
pub struct TzapBrowserCallback {
    pub state: String,
    pub handoff_code: String,
}

/// Parses a complete callback against the exact redirect saved before launch.
pub fn parse_browser_callback(callback_url: &str, expected_redirect: &str) -> Result<TzapBrowserCallback, TzapAuthError> {
    let url = validate_callback_base(callback_url, expected_redirect)?;
    let query = url.query().ok_or(TzapAuthError::InvalidCallbackUrl)?;
    // Url's form decoder is intentionally forgiving of broken escapes. Check
    // syntax first, then use its established, single-pass UTF-8/form decoder.
    validate_percent_escapes(query)?;
    let mut state = None;
    let mut handoff_code = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "state" => &mut state,
            "handoff_code" => &mut handoff_code,
            "relay_body" | "access_token" | "session_token" | "id_token" | "refresh_token" => return Err(TzapAuthError::SessionTokenInCallbackUrl),
            _ => return Err(TzapAuthError::InvalidCallbackUrl),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(TzapAuthError::InvalidCallbackUrl);
        }
    }
    let state = state.ok_or(TzapAuthError::InvalidCallbackUrl)?;
    let handoff_code = handoff_code.ok_or(TzapAuthError::InvalidCallbackUrl)?;
    validate_oauth_state(&state)?;
    validate_handoff_code(&handoff_code)?;
    Ok(TzapBrowserCallback { state, handoff_code })
}

pub fn validate_handoff_code(code: &str) -> Result<(), TzapAuthError> {
    if !(16..=2048).contains(&code.len()) || !code.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
        return Err(TzapAuthError::InvalidHandoffCode);
    }
    Ok(())
}

/// Desktop passes a query-free, sanitized URL beside typed callback fields.
/// Full browser URLs must instead pass the complete two-field parser.
pub(crate) fn validate_callback_binding(callback_url: &str, expected_redirect: &str, expected_state: &str) -> Result<(), TzapAuthError> {
    let url = validate_callback_base(callback_url, expected_redirect)?;
    if url.query().is_some() {
        let parsed = parse_browser_callback(callback_url, expected_redirect)?;
        if parsed.state != expected_state {
            return Err(TzapAuthError::UnknownState);
        }
    }
    Ok(())
}

fn validate_callback_base(callback_url: &str, expected_redirect: &str) -> Result<url::Url, TzapAuthError> {
    if callback_url.len() > MAX_CALLBACK_URL_BYTES
        || callback_url.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || callback_url.contains('#')
        || expected_redirect.contains(['?', '#'])
    {
        return Err(TzapAuthError::InvalidCallbackUrl);
    }
    let base = callback_url.split_once('?').map_or(callback_url, |(base, _)| base);
    if base != expected_redirect {
        return Err(TzapAuthError::RedirectUriMismatch);
    }
    let url = url::Url::parse(callback_url).map_err(|_| TzapAuthError::InvalidCallbackUrl)?;
    if !url.username().is_empty() || url.password().is_some() || url.host().is_none() {
        return Err(TzapAuthError::InvalidCallbackUrl);
    }
    Ok(url)
}

fn validate_percent_escapes(query: &str) -> Result<(), TzapAuthError> {
    if query.split('&').any(str::is_empty) {
        return Err(TzapAuthError::InvalidCallbackUrl);
    }
    let bytes = query.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if !bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit) || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit) {
                return Err(TzapAuthError::InvalidCallbackUrl);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    const CODE: &str = "tzap_handoff_fixture_only";

    #[test]
    fn exact_manual_ipv4_and_ipv6_callbacks_decode_once() {
        for base in ["tzap://auth/callback", "http://127.0.0.1:49152/auth/callback", "http://[::1]:49153/auth/callback"] {
            let callback = parse_browser_callback(&format!("{base}?handoff_code={CODE}&st%61te={STATE}"), base).unwrap();
            assert_eq!(callback.state, STATE);
            assert_eq!(callback.handoff_code, CODE);
        }
    }

    #[test]
    fn malformed_duplicate_unknown_and_secret_fields_are_rejected() {
        let base = "tzap://auth/callback";
        let valid = format!("{base}?state={STATE}&handoff_code={CODE}");
        for invalid in [
            format!("{valid}&state={STATE}"),
            format!("{valid}&st%61te={STATE}"),
            format!("{valid}&handoff_code={CODE}"),
            format!("{valid}&result=completed"),
            format!("{valid}&%61ccess_token=fixture_only"),
            format!("{valid}&provider_code=fixture_only"),
            format!("{valid}&"),
            format!("{valid}#"),
            format!("{valid}\n"),
            format!("{base}?state={STATE}&handoff_code=%FF"),
            format!("{base}?state={STATE}&handoff_code=fixture%00code1234567890"),
            format!("{base}?state={STATE}&handoff_code=fixture%2520code1234567890"),
            format!("{base}?state={STATE}&handoff_code=fixture%2code1234567890"),
            format!("{base}?state={STATE}&handoff_code=fixture%"),
            format!("{base}?state={STATE}&handoff_code=fixture+code1234567890"),
            format!("{base}?state={STATE}&handoff_code={}", "x".repeat(2049)),
            format!("{base}?state={STATE}&handoff_code={}", "x".repeat(MAX_CALLBACK_URL_BYTES)),
            format!("{base}?state={STATE}"),
            format!("{base}?handoff_code={CODE}"),
            base.to_owned(),
        ] {
            assert!(parse_browser_callback(&invalid, base).is_err());
        }
    }

    #[test]
    fn exact_raw_redirect_binding_rejects_url_normalization_and_authority_tricks() {
        let base = "http://127.0.0.1:49152/auth/callback";
        for wrong in [
            "http://localhost:49152/auth/callback",
            "http://127.0.0.1:49153/auth/callback",
            "http://127.0.0.1:49152/auth/../auth/callback",
            "http://127.0.0.1:49152/auth/call%62ack",
            "http://fixture@127.0.0.1:49152/auth/callback",
            "http://127.0.0.1:49152.evil.invalid/auth/callback",
            "http://127.0.0.1:49152/auth/callback/",
        ] {
            assert!(parse_browser_callback(&format!("{wrong}?state={STATE}&handoff_code={CODE}"), base).is_err());
        }
    }
}
