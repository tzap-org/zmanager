//! Shared HTTP client plumbing for TZAP client modules.

use crate::auth_client::{
    TzapAuthCancellation, TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapAuthRequestOptions,
    TzapBearerToken,
};
use serde_json::Value;

/// Sends a JSON-capable TZAP HTTP request and returns the raw response.
pub(crate) fn send_json_request<T: TzapAuthHttpTransport>(
    transport: &T,
    method: TzapAuthHttpMethod,
    base_url: &str,
    path: &str,
    bearer_token: Option<TzapBearerToken>,
    body: Option<Value>,
) -> Result<TzapAuthHttpResponse, TzapAuthError> {
    send_json_request_with_options(transport, method, base_url, path, bearer_token, body, TzapAuthRequestOptions::default())
}

pub(crate) fn send_json_request_with_options<T: TzapAuthHttpTransport>(
    transport: &T,
    method: TzapAuthHttpMethod,
    base_url: &str,
    path: &str,
    bearer_token: Option<TzapBearerToken>,
    body: Option<Value>,
    options: TzapAuthRequestOptions,
) -> Result<TzapAuthHttpResponse, TzapAuthError> {
    send_json_request_with_headers(transport, method, base_url, path, bearer_token, body, Vec::new(), options)
}

/// Same as [`send_json_request_with_options`], but attaches extra request
/// headers (design need: `If-Match` on the backup PUT endpoints).
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_json_request_with_headers<T: TzapAuthHttpTransport>(
    transport: &T,
    method: TzapAuthHttpMethod,
    base_url: &str,
    path: &str,
    bearer_token: Option<TzapBearerToken>,
    body: Option<Value>,
    headers: Vec<(String, String)>,
    options: TzapAuthRequestOptions,
) -> Result<TzapAuthHttpResponse, TzapAuthError> {
    let request = TzapAuthHttpRequest { method, url: format!("{}{}", trim_trailing_slash(base_url), path), bearer_token, body, options, headers };
    if let Some(token) = &request.bearer_token {
        token.require_destination(&request.url)?;
    }
    let mut attempts = 0_u8;
    loop {
        if request.options.cancellation.as_ref().is_some_and(TzapAuthCancellation::is_cancelled) {
            return Err(TzapAuthError::Cancelled);
        }
        attempts = attempts.saturating_add(1);
        match transport.send(&request) {
            Ok(response) => {
                if request.options.cancellation.as_ref().is_some_and(TzapAuthCancellation::is_cancelled) {
                    return Err(TzapAuthError::Cancelled);
                }
                if attempts < request.options.max_attempts.max(1) && request.options.should_retry(method, response.status_code) {
                    std::thread::sleep(request.options.retry_backoff);
                    continue;
                }
                return Ok(response);
            }
            Err(error) => {
                if request.options.cancellation.as_ref().is_some_and(TzapAuthCancellation::is_cancelled) {
                    return Err(TzapAuthError::Cancelled);
                }
                if attempts < request.options.max_attempts.max(1)
                    && matches!(error, TzapAuthError::Transport { .. })
                    && matches!(method, TzapAuthHttpMethod::Get)
                {
                    std::thread::sleep(request.options.retry_backoff);
                    continue;
                }
                return Err(error);
            }
        }
    }
}

/// Requires a 2xx status code, otherwise maps the response into an error.
pub(crate) fn require_success<E>(
    response: TzapAuthHttpResponse,
    error_from_status: impl FnOnce(u16, &TzapAuthHttpResponse) -> E,
) -> Result<TzapAuthHttpResponse, E> {
    if (200..=299).contains(&response.status_code) { Ok(response) } else { Err(error_from_status(response.status_code, &response)) }
}

/// Strips trailing slashes from a base URL before path concatenation.
pub(crate) fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// Trims an HTTP error body and returns it only when it is non-empty.
pub(crate) fn http_error_body(bytes: &[u8]) -> Option<String> {
    let value = String::from_utf8_lossy(bytes).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}
