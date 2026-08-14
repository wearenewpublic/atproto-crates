//! Response security headers, applied once for the whole server.
//!
//! This PDS serves HTML from three places -- the OAuth consent screen, the
//! account portal, and the admin dashboard -- and none of them sent a single
//! security header. The consent screen is the one that matters most: it is
//! where an account holder types their password and approves an application's
//! access, it lives on the PDS origin alongside the portal session cookie, and
//! it could be framed by any page on the internet.
//!
//! # Why a layer and not three handlers
//!
//! Because the alternative is the failure this codebase keeps repeating: a
//! correct thing invoked at some call sites and not others. `getBlob` already
//! sets its own headers and got them right; the three HTML pages each would
//! have had to remember, and a fourth page added later would have had to
//! remember too. A layer means a route cannot be added without them.
//!
//! Handlers that set their own value keep it -- every header here is inserted
//! only when absent, so `getBlob`'s stricter `default-src 'none'; sandbox`
//! survives contact with this.
//!
//! # What is sent
//!
//! `X-Content-Type-Options: nosniff` on everything. A JSON error body that a
//! browser decides to render as HTML is the whole of that class of bug, and it
//! costs nothing to refuse.
//!
//! On `text/html` responses only:
//!
//! - `Content-Security-Policy` -- see [`HTML_CSP`].
//! - `X-Frame-Options: DENY`, which `frame-ancestors` already covers for
//!   anything current. It is here for browsers that predate it, since the cost
//!   is a header and the thing it prevents is a password prompt in an invisible
//!   frame.
//! - `Referrer-Policy: no-referrer`. The consent URL carries a `request_uri`
//!   that names a pending authorization, and the page links out to a client's
//!   `client_id`; neither should travel in a `Referer`.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// The policy for this server's own HTML.
///
/// `font-src 'self'` is the one directive that is not merely permissive: the
/// portal serves a typeface from `/static/fonts/` and would otherwise fall
/// back to `default-src 'none'`, under which no font loads at all -- not even
/// a `data:` URI. `'self'` and nothing more, so a stylesheet that ever tried
/// to pull a face off a CDN is refused rather than quietly working.
///
/// `default-src 'none'` and then only what the pages actually use. These are
/// server-rendered pages with no assets: no images, no fonts, no stylesheets,
/// no XHR except the consent form's own submit, which `connect-src 'self'`
/// covers.
///
/// # `'unsafe-inline'` is doing real work here and is not a placeholder
///
/// Both `style-src` and `script-src` need it. Every page carries an inline
/// `<style>` block, and the consent page carries an inline `<script>` plus an
/// `onsubmit=` attribute that lifts its form POST into the JSON the authorize
/// endpoint expects.
///
/// A nonce would cover the `<script>` element but not the `onsubmit` attribute
/// -- inline event handlers need `'unsafe-hashes'` with a hash of each handler,
/// or no attribute at all. Tightening this means moving that handler into the
/// script block and hashing the block, which is worth doing and is a change to
/// the most security-sensitive form on the server, so it is not folded in here.
///
/// # `img-src 'self' data:` and not a step further
///
/// The repository browser shows a small icon for each NSID authority. Those are
/// served by this server from its own cache rather than hot-linked, so the
/// browser never contacts a third party for them — which matters on a signed-in
/// page, where a remote image tells its host when the account holder opened
/// their own repository, and gives an injected `<img>` somewhere to report to.
/// `data:` is here for the same reason a generated placeholder is: an icon this
/// server draws needs no round trip at all.
///
/// What the policy still buys with `'unsafe-inline'` present is the part that
/// does not depend on it: `frame-ancestors 'none'` makes the consent screen
/// unframeable, `form-action 'self'` means an injected `<form>` cannot post the
/// holder's password to another origin, and `base-uri 'none'` stops a `<base>`
/// tag re-pointing the form's relative action.
pub const HTML_CSP: &str = "default-src 'none'; \
     img-src 'self' data:; \
     font-src 'self'; \
     style-src 'unsafe-inline'; \
     script-src 'unsafe-inline'; \
     connect-src 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'; \
     base-uri 'none'";

/// [`HTML_CSP`] with `form-action` widened to any HTTPS origin, for the
/// delegate handle-entry page and nothing else.
///
/// That page's form posts here and this server answers `303` to the delegate's
/// own authorization server -- a different origin, and one not known until the
/// handle has been resolved, so it cannot be named ahead of time.
///
/// A browser enforces `form-action` against the *end* of a redirect chain that
/// began with a form submission, not just its first hop. Under `'self'` Chrome
/// abandons the navigation silently: no console error the submitter sees, no
/// request to the peer, a page that appears to do nothing. Delegated sign-in
/// was completely broken by this and looked like a server fault. Verified by
/// A/B -- same page, same `303`, only this directive changed.
///
/// The consent screen has the same shape and solves it differently, with a
/// `fetch` and a `location` assignment, because a navigation is not a form
/// submission. That costs a script, and the delegate page is required to work
/// without one.
///
/// Widening it here is cheap: the page carries one text field for a handle and
/// no password, its only interpolated value is a `login_hint` that
/// `prefill_identifier` has already validated, and anyone who could inject a
/// form into it could exfiltrate through `script-src 'unsafe-inline'` anyway.
/// The pages that do take a password keep [`HTML_CSP`].
pub const DELEGATION_START_CSP: &str = "default-src 'none'; \
     img-src 'self' data:; \
     font-src 'self'; \
     style-src 'unsafe-inline'; \
     script-src 'unsafe-inline'; \
     connect-src 'self'; \
     form-action 'self' https:; \
     frame-ancestors 'none'; \
     base-uri 'none'";

/// Add the headers above to every response that does not already carry them.
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let is_html = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
        });

    let headers = response.headers_mut();
    headers
        .entry(X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));

    if is_html {
        headers
            .entry(CONTENT_SECURITY_POLICY)
            .or_insert(HeaderValue::from_static(HTML_CSP));
        headers
            .entry(X_FRAME_OPTIONS)
            .or_insert(HeaderValue::from_static("DENY"));
        headers
            .entry(REFERRER_POLICY)
            .or_insert(HeaderValue::from_static("no-referrer"));
    }

    response
}
