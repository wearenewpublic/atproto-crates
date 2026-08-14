# Account portal style guide

Every block, component and element the account portal is built from, on one
page. Open `index.html` in a browser — it is self-contained, needs no server
and no build step.

| File | What it is |
| --- | --- |
| `index.html` | The style guide. Hand-maintained; edit it directly. |
| `.impeccable.md` | Design context: who this is for, how it should feel, what it must not become. |
| `README.md` | This file. |

## Editing it

It is an ordinary HTML file. Open it, change it, reload the browser, commit.
There is no generator, no test, and nothing to run.

The `<style>` block at the top is a **copy** of the stylesheet that `page()`
inlines into every portal response, in `src/http/portal.rs`. That function is
the source of truth. This is a reference copy, and keeping the two in step is
manual:

> **When you change `page()`, mirror the change here — and the reverse.**
> Nothing enforces it. If they diverge, this document quietly stops describing
> the thing it claims to describe, which is the one failure a style guide
> cannot tolerate.

To add a component:

1. Add the rule to `page()` in `src/http/portal.rs`.
2. Mirror it into the `<style>` block here.
3. Add a block for it in `<main>`, with a `<details>Markup</details>` sample so
   the component can be copied rather than just looked at.

## What it covers

Thirteen components in four groups — foundations, containers, telling the
holder something, and data and controls: shell and measure, headings and text,
adaptive states, cards, navigation, disclosure, notices, the one-time secret
reveal, explanation lists, tables (standard, empty state, grouped with
authority badges), forms and buttons.

The guide is built out of the components it documents — its own headings, cards
and notes are portal classes, and it adds no CSS of its own. Assembling it is
therefore its own check that the pieces compose.

Two things on the page are examples rather than working controls: the nav's
links point at `#nav`, and the forms post nowhere. A control that appeared to
work and silently did nothing would be worse than one that visibly does not.

## Scope

The portal only — the pages under `/account`. The OAuth consent screen
(`src/oauth/consent.rs`), the delegate sign-in page (`src/oauth/delegation.rs`)
and the operator dashboard (`src/admin/dashboard.rs`) each carry their own
stylesheet and are deliberately not covered. See `.impeccable.md` for why.

## Checking it against the real thing

Since nothing enforces the copy, the honest way to verify is to look at both:

```sh
# Run the PDS locally, sign in, and compare the rendered pages against this
# file. The portal's CSS is served inline, so "view source" on any /account
# page shows the stylesheet this one should match.
cargo run --features clap --bin pds
```

## How far along the design direction this is

`.impeccable.md` sets the target. A `/critique` pass and the fixes from it
moved three of its four points:

| Direction | State |
| --- | --- |
| Dark as a drawn palette, not overrides | **Done.** Both themes are token sets; every value clears WCAG AA. |
| A deliberate type scale | **Done.** Five `rem` steps replacing twelve accidental `em` sizes. |
| Interaction states | **Done.** `:focus-visible`, `:hover`, `:active`, reduced-motion. |
| A distributed typeface | **Not started.** Still the system stack; needs `font-src` and an asset route. |

One decision worth knowing before you change widths: the body, cards and card
contents all expand together, with no reading measure between the shell and the
text. A line of prose therefore runs about 130 characters on a wide display.
That is deliberate — using the width was chosen over the conventional 65–75
character measure. The dial is a `max-width` on `section` if that changes.
