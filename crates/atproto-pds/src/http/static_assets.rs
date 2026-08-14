//! Statically served assets: `/static/…`.
//!
//! Everything the portal serves that is a fixed file rather than a rendered
//! page — fonts today, and stylesheets or images if they are ever split out of
//! the inline `<style>`. NSID authority icons are deliberately *not* here:
//! those are fetched per-authority, cached with a TTL and gated on a session,
//! which makes them dynamic content that happens to be an image. See
//! [`crate::http::icons`].
//!
//! # Why a route and not a data URI
//!
//! The portal's stylesheet is inlined into every response, so it is never
//! cached. A font embedded in it as a `data:` URI would therefore ship its
//! bytes on *every page view* — for a console meant to be fast, the worst of
//! the available options. A route is fetched once and cached for the session,
//! which is the whole reason `font-src 'self'` is in the policy rather than
//! `font-src data:`.
//!
//! # Why the bytes are in the binary
//!
//! `include_bytes!`, not a file read. The PDS ships as a single container with
//! one volume holding account data; a font read from disk at request time is a
//! deployment that can start successfully and then serve an unstyled portal
//! because an asset was not copied. Embedded, the font cannot be missing.
//! At 12 KB it costs nothing to carry.
//!
//! # Why this one is not behind a session
//!
//! Unlike [`crate::http::icons`], which serves repository icons and requires a
//! signed-in holder, a typeface is requested by the sign-in page itself —
//! before anyone has a session. Gating it would leave the one page every
//! visitor sees rendering in a fallback face.
//!
//! Nothing here is user data. The response is a constant, identical for every
//! caller, and reveals only which font this server uses.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// JetBrains Mono, variable weight, subset to what the portal renders.
///
/// See `assets/fonts/README.md` for the subsetting command and the licences.
const JETBRAINS_MONO: &[u8] = include_bytes!("../../assets/fonts/jetbrains-mono-var.woff2");

/// Archivo, one file per weight -- upstream ships no variable cut.
///
/// Four weights because the design uses three of them to carry hierarchy
/// (400 body, 500 label, 600 heading) and the fourth is what `<b>` resolves
/// to. A real italic rather than a synthesised oblique, because the spaces
/// pages set `<em>` and a sheared roman looks like a rendering fault.
const ARCHIVO_400: &[u8] = include_bytes!("../../assets/fonts/archivo-400.woff2");
const ARCHIVO_400_ITALIC: &[u8] = include_bytes!("../../assets/fonts/archivo-400-italic.woff2");
const ARCHIVO_500: &[u8] = include_bytes!("../../assets/fonts/archivo-500.woff2");
const ARCHIVO_600: &[u8] = include_bytes!("../../assets/fonts/archivo-600.woff2");
const ARCHIVO_700: &[u8] = include_bytes!("../../assets/fonts/archivo-700.woff2");

/// How long a browser may keep a font.
///
/// A year, and immutable. The file name changes when the font does — there is
/// no revalidation to do, and a font is the least interesting thing for a
/// browser to ask about twice.
const CACHE: &str = "public, max-age=31536000, immutable";

/// `GET /static/{path}` — one asset, by path.
///
/// Matched against a fixed list rather than joined onto a directory. The path
/// arrives from the request, and a filesystem path built from caller-supplied
/// text is the whole of the directory-traversal class of bug; a `match` cannot
/// express `../../etc/passwd` at all. It also means the set of things this
/// server will serve is readable in one place.
pub async fn asset(Path(path): Path<String>) -> Response {
    let (body, mime): (&'static [u8], &'static str) = match path.as_str() {
        "fonts/jetbrains-mono-var.woff2" => (JETBRAINS_MONO, "font/woff2"),
        "fonts/archivo-400.woff2" => (ARCHIVO_400, "font/woff2"),
        "fonts/archivo-400-italic.woff2" => (ARCHIVO_400_ITALIC, "font/woff2"),
        "fonts/archivo-500.woff2" => (ARCHIVO_500, "font/woff2"),
        "fonts/archivo-600.woff2" => (ARCHIVO_600, "font/woff2"),
        "fonts/archivo-700.woff2" => (ARCHIVO_700, "font/woff2"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                "no such asset on this server".to_string(),
            )
                .into_response();
        }
    };

    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(mime)),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
            // The stylesheet requests this same-origin and the CSP allows only
            // that, but a font is a static asset an operator may put a CDN in
            // front of, and one that is byte-identical for everyone is safe to
            // share.
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            ),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// The bytes reach the browser as a woff2, cacheable for a year.
    #[tokio::test]
    async fn a_known_font_is_served_with_its_type_and_a_long_cache() {
        let response = asset(Path("fonts/jetbrains-mono-var.woff2".to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "font/woff2");
        assert_eq!(response.headers()[header::CACHE_CONTROL], CACHE);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        // `wOF2` — the file really is what the content type claims.
        assert_eq!(&body[..4], b"wOF2");
        assert!(body.len() > 4096, "the font did not come through whole");
    }

    /// The name is matched, never joined onto a path.
    #[tokio::test]
    async fn anything_not_on_the_list_is_a_404_including_a_traversal() {
        for name in [
            "../../../etc/passwd",
            "..%2f..%2fCargo.toml",
            "fonts/jetbrains-mono-var.woff2.bak",
            "",
        ] {
            let response = asset(Path(name.to_string())).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{name:?} was served something"
            );
        }
    }
}
