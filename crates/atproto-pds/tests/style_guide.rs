//! Guards for `docs/style-guide/index.html`.
//!
//! The style guide is hand-maintained and standalone -- it is opened straight
//! from disk, so it embeds its own copy of the portal stylesheet rather than
//! linking one. That copy is the whole risk: a reference document that has
//! quietly stopped matching the thing it documents is worse than no reference
//! document, because it is still believed.
//!
//! These tests are the "nothing checks" the guide's own header used to admit
//! to. Each one exists because the failure it describes has already happened
//! at least once.

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let full = crate_dir().join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {}: {e}", full.display()))
}

/// The contents of the nth `<style>` element, by document order.
///
/// Comments are removed first. The guide's own header comment explains how to
/// resync the mirror and says the word `<style>` while doing it, which is
/// enough to make a naive search find the prose instead of the element -- the
/// same false match that once spliced this file's `<head>` into its stylesheet.
/// The tag is also required to start a line, as it does in the real markup.
fn style_block(html: &str, index: usize) -> String {
    let live = strip_inert(html);
    let mut blocks = Vec::new();
    for (i, _) in live.match_indices("<style>") {
        if i != 0 && !live[..i].ends_with('\n') {
            continue;
        }
        let after = &live[i + "<style>".len()..];
        let close = after.find("</style>").expect("a closing </style>");
        blocks.push(after[..close].to_string());
    }
    blocks
        .into_iter()
        .nth(index)
        .unwrap_or_else(|| panic!("expected at least {} <style> element(s)", index + 1))
}

/// Remove HTML comments and `<textarea>` bodies.
///
/// Both hold markup that is being *shown* rather than used -- the guide's
/// Markup samples are full of `href="{href}"` and `<a href="#nav">`. Scanning
/// them as if they were live markup is how the dead-link guard below first
/// managed to fail on the guide's own documentation of itself.
fn strip_inert(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    loop {
        let comment = rest.find("<!--");
        let textarea = rest.find("<textarea");
        let (start, close, skip) = match (comment, textarea) {
            (None, None) => break,
            (Some(c), None) => (c, "-->", "-->".len()),
            (None, Some(t)) => (t, "</textarea>", "</textarea>".len()),
            (Some(c), Some(t)) if c < t => (c, "-->", "-->".len()),
            (Some(_), Some(t)) => (t, "</textarea>", "</textarea>".len()),
        };
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        match after.find(close) {
            Some(end) => rest = &after[end + skip..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The guide's mirrored stylesheet is byte-identical to the real one.
///
/// `page()` serves `portal.css` with its comments stripped; the guide embeds it
/// with them intact, because it is read by people. Both derive from the same
/// file, and this is what keeps that true.
#[test]
fn style_guide_mirrors_the_portal_stylesheet() {
    let css = read("src/http/portal.css");
    let html = read("docs/style-guide/index.html");
    let mirrored = style_block(&html, 0);

    assert_eq!(
        mirrored.trim(),
        css.trim(),
        "docs/style-guide/index.html has drifted from src/http/portal.css.\n\
         The first <style> block in the guide is a verbatim copy of that file.\n\
         To resync it, replace that block's contents with the file's contents."
    );
}

/// Every in-page link resolves to an element that exists.
///
/// The guide is navigated by its contents list and by a back-to-contents link
/// in every heading, so a broken fragment is not cosmetic -- it is the document
/// failing at the one interaction it has. Four of these shipped once already.
#[test]
fn style_guide_has_no_dead_links() {
    let html = read("docs/style-guide/index.html");
    let live = strip_inert(&html);

    let ids: Vec<String> = live
        .match_indices("id=\"")
        .filter_map(|(i, _)| {
            let after = &live[i + 4..];
            after.find('"').map(|end| after[..end].to_string())
        })
        .collect();

    let mut dead = Vec::new();
    for (i, _) in live.match_indices("href=\"#") {
        let after = &live[i + 7..];
        let Some(end) = after.find('"') else { continue };
        let target = &after[..end];
        if target.is_empty() {
            continue;
        }
        if !ids.iter().any(|id| id == target) {
            dead.push(target.to_string());
        }
    }
    dead.sort();
    dead.dedup();

    assert!(
        dead.is_empty(),
        "style guide links to fragments that do not exist: {dead:?}"
    );
}

/// No two controls share an accessible name.
///
/// Ten Markup samples once carried the identical label "markup for this
/// component", which left a screen-reader user tabbing through ten
/// indistinguishable editable fields.
#[test]
fn style_guide_labels_are_distinct() {
    let html = read("docs/style-guide/index.html");

    let mut labels: Vec<String> = html
        .match_indices("aria-label=\"")
        .filter_map(|(i, _)| {
            let after = &html[i + 12..];
            after.find('"').map(|end| after[..end].to_string())
        })
        .collect();
    labels.sort();

    let mut duplicated: Vec<&String> = labels
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| &w[0])
        .collect();
    duplicated.dedup();

    // The back-to-contents arrow is deliberately repeated: it is the same
    // destination from every section, and thirteen differently-worded names
    // for one target would be worse than one shared name.
    duplicated.retain(|l| l.as_str() != "Back to contents");

    assert!(
        duplicated.is_empty(),
        "these accessible names are used by more than one control: {duplicated:?}"
    );
}

/// The guide's fonts are present, so it renders standalone.
///
/// The stylesheet names each face twice -- an absolute `/static/` URL the
/// server answers, and a relative one for this directory. The relative
/// candidate only works if the files are actually here.
#[test]
fn style_guide_carries_its_own_fonts() {
    let css = read("src/http/portal.css");
    let dir = crate_dir().join("docs/style-guide");

    let mut checked = 0;
    for (i, _) in css.match_indices("url(\"fonts/") {
        let after = &css[i + "url(\"".len()..];
        let end = after.find('"').expect("a closed url()");
        let rel = &after[..end];
        assert!(
            Path::new(&dir.join(rel)).exists(),
            "docs/style-guide/{rel} is referenced by the stylesheet but missing"
        );
        checked += 1;
    }
    assert!(checked > 0, "expected the stylesheet to reference fonts");
}
