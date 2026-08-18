// The legal-page rule, on the bytes a client site is about to publish (#147).
//
// ── Why this file is a COPY, and what keeps it honest ────────────────────
//
// core/src/lib/legal.json is the one source for the placeholder list, the legal
// page names, the shape of the review comment, the review banner's slot group
// and the ways an element can be hidden. core/src/lib/guards.ts imports it and
// templates/validate.mjs reads it off disk, and #126 exists because those two
// used to carry a copy each and the copies disagreed about `[DATE]`.
//
// Neither of them runs in a CLIENT's repository. The publisher does, standalone,
// from a tag, in an agency's Actions runner, with no build step and no core/ to
// import -- the same constraint that gave #138 its own tokeniser in html.mjs. So
// the data is vendored here, and the copy is kept honest by two things that are
// checks rather than comments asking people to remember:
//
//   tests/publisher/legal-artifact.test.mjs compares every list below against
//     core/src/lib/legal.json, field by field. Editing legal.json without
//     editing this file turns the suite red.
//   this file is a released publisher file, so its bytes are hashed into
//     .github/publisher-release.json. Editing it without cutting a release turns
//     the drift check red, which is what stops the fix from looking shipped.
//
// ── WHICH WAY IT FAILS, which is the substance of the issue ──────────────
//
// A publish that refuses on a legal page also blocks an urgent fix to an
// unrelated page on a live client business, and CLAUDE.md hard rule 4 says an
// unfinished policy is safer than a confidently wrong one. Both are true, and
// the way out is not to pick a side: it is to narrow WHAT IS DETECTED until
// refusing costs nothing legitimate.
//
// A legal page has two stable states, and this guard is silent in both:
//
//   UNFINISHED  straight from the template. Every placeholder standing, the
//               visible review banner up. This is what an agency publishes for
//               a client review window, and it is the state hard rule 4 wants.
//   FINISHED    a person filled the four facts after legal review and dropped
//               the banner, which SLOTS.md section 6 says is how the banner
//               goes. A finished policy names a company, a jurisdiction, an
//               address and a date -- that is what finishing it MEANS.
//
// What fails is the state that is neither: a page that still DECLARES itself
// unreviewed -- a placeholder standing, or the banner up -- while some of the
// facts those placeholders stand in for have already been supplied. That is a
// document contradicting itself, no legitimate site stays in it, and one edit
// leaves it in either direction (restore the marker, or finish the page and drop
// the banner). So the answer to "does this block an urgent fix to index.html" is
// only if privacy.html is genuinely half-edited, and the same run would refuse
// it tomorrow anyway.
//
// So: it fails the publish, exactly like every other artifact rule, and nothing
// is uploaded. A warning was the obvious alternative and it is worse than it
// looks -- the whole reason this issue exists is that a legal page reaching the
// public unchecked is invisible, and a `::warning::` in a run log an agency does
// not read is the same invisibility with a receipt.
//
// ── WHAT THIS CANNOT SEE, stated rather than implied ─────────────────────
//
// A page where every placeholder was replaced with invented specifics AND the
// banner was removed is byte-identical to a page a lawyer signed off, and this
// guard passes it. The publisher has one document and no original to diff
// against, which is precisely what core/src/lib/guards.ts DOES have -- its
// INVENTED_SPECIFICS rules fire on prose a proposal ADDED. Porting those here
// without a diff would fail every finished policy in the fleet, and softening
// them into "does this prose look invented" would be a guard that fails open
// while looking thorough. The honest boundary is the contradiction, and the
// proposal path stays the layer that watches the invention happen.

import { blankComments, comments, scanHtml } from "./html.mjs";

/** Where the lists below come from. Named so a reader can go and check. */
export const VENDORED_FROM = "core/src/lib/legal.json";

export const LEGAL_PLACEHOLDERS = Object.freeze(["[ENTITY]", "[JURISDICTION]", "[CONTACT]", "[DATE]"]);

/** The page names the templates ship. A convention, not an invariant. */
export const LEGAL_PAGES = Object.freeze(["privacy.html", "terms.html"]);

/** Every one must match, case-insensitively, inside ONE comment. */
export const LEGAL_REVIEW_MARKERS = Object.freeze(["review", "lawyer|legal"]);

export const REVIEW_BANNER_GROUP = "rs.review_banner";

export const HIDDEN_STYLES = Object.freeze([
  "display:none",
  "visibility:hidden",
  "visibility:collapse",
  "opacity:0",
  "font-size:0",
]);

export const HIDDEN_CLASSES = Object.freeze([
  "hidden",
  "invisible",
  "sr-only",
  "collapse",
  "opacity-0",
  "scale-0",
  "h-0",
  "w-0",
  "max-h-0",
]);

/**
 * Whether a document carries the review-required header, matched by SHAPE.
 *
 * Every marker must appear in one comment. Requiring all of them is what keeps
 * this from misfiring: `<!-- reviewed by the design team -->` on a marketing
 * page would otherwise turn that page into a legal page and start failing
 * publishes over it, which is how a guard gets switched off.
 */
export function hasReviewComment(html) {
  const markers = LEGAL_REVIEW_MARKERS.map((source) => new RegExp(source, "i"));
  return comments(html).some((comment) => markers.every((marker) => marker.test(comment)));
}

/**
 * Whether this file is a legal page, BY NAME or BY CONTENT.
 *
 * The same two questions guards.ts asks, and deliberately so: a page the runtime
 * guard treats as legal must be a page this one treats as legal, or an edit
 * refused in the panel is a publish accepted at the tag. A Rocket Site is
 * hand-editable HTML by design, so `legal.html` and `privacy-policy.html` are
 * things agencies really write.
 */
export function isLegalPage(relPath, html) {
  const base = String(relPath ?? "").split("/").pop()?.toLowerCase() ?? "";
  if (LEGAL_PAGES.includes(base)) return true;
  return typeof html === "string" && hasReviewComment(html);
}

/**
 * Placeholders still standing where a READER can see them.
 *
 * Comments are blanked first, and that is the comment-hidden bypass (#126, and
 * #89 one layer down): the templates' own review header names all four
 * placeholders in prose, so reading the raw file would count them forever, and
 * moving `[ENTITY]` into a comment would leave a raw count untouched while the
 * policy on screen reads as finished and names a company nobody verified.
 */
export function visiblePlaceholders(html) {
  const visible = blankComments(String(html ?? ""));
  return LEGAL_PLACEHOLDERS.filter((placeholder) => visible.includes(placeholder));
}

/** Every element carrying the review banner's slot group, in document order. */
export function reviewBanners(html) {
  return scanHtml(html).tags.filter((tag) => (tag.attrs[`data-rs-slot-group`] ?? "").trim() === REVIEW_BANNER_GROUP);
}

/**
 * Ways this element is on the page and not on the screen.
 *
 * A banner that is present and invisible is worse than one that was removed: the
 * page passes every check that asks whether the warning is there, and the person
 * previewing the client's site in a browser -- who is exactly who it is for --
 * sees a finished-looking policy.
 */
export function hiddenReasons(tag) {
  const attrs = tag?.attrs ?? {};
  const reasons = [];
  if ("hidden" in attrs) reasons.push("the hidden attribute");
  if (String(attrs["aria-hidden"] ?? "").trim().toLowerCase() === "true") reasons.push('aria-hidden="true"');

  const style = String(attrs["style"] ?? "").toLowerCase().replace(/\s+/g, "");
  for (const pattern of HIDDEN_STYLES) if (style.includes(pattern)) reasons.push(pattern);

  const classes = new Set(String(attrs["class"] ?? "").split(/\s+/).filter(Boolean));
  for (const cls of HIDDEN_CLASSES) if (classes.has(cls)) reasons.push(`the "${cls}" class`);
  return reasons;
}

const list = (items) => items.join(", ");

/**
 * Everything wrong with one legal page, as `{ index, message }` so the caller
 * can turn an offset into a line number with its own reader.
 *
 * Returns [] for a page that is not a legal page, for an untouched template, and
 * for a page a person genuinely finished. See the header for why those three are
 * the same answer.
 */
export function legalPageProblems(relPath, html) {
  const text = String(html ?? "");
  if (!isLegalPage(relPath, text)) return [];

  const problems = [];
  const banners = reviewBanners(text);
  const visible = visiblePlaceholders(text);
  const filled = LEGAL_PLACEHOLDERS.filter((placeholder) => !visible.includes(placeholder));

  // 1. Present, and invisible. Checked whatever the placeholders say: a banner
  //    that is on the page and not on the screen is never the right answer --
  //    either the page is unfinished and the warning belongs on screen, or it is
  //    finished and the element is deleted.
  for (const banner of banners) {
    const reasons = hiddenReasons(banner);
    if (reasons.length === 0) continue;
    problems.push({
      index: banner.start,
      message:
        `hides its legal review banner with ${list(reasons)}. The banner says this page's legal details ` +
        `have not been reviewed, and an invisible warning does not protect the person previewing this ` +
        `site in a browser -- which is exactly who it is for. Remove the element carrying ` +
        `data-rs-slot-group="${REVIEW_BANNER_GROUP}" once a person has genuinely filled the legal ` +
        `details, and until then leave it visible.`,
    });
  }

  // 2. The contradiction. The page still declares itself unreviewed -- a
  //    placeholder standing, or the banner up -- while facts those placeholders
  //    stand in for have been supplied. Neither half alone is a problem: an
  //    untouched template has every placeholder AND the banner, and a finished
  //    page has neither.
  const declaresUnreviewed = visible.length > 0 || banners.length > 0;
  if (filled.length > 0 && declaresUnreviewed) {
    const at = visible.length > 0 ? blankComments(text).indexOf(visible[0]) : banners[0].start;
    const stillThere =
      visible.length > 0
        ? `${list(visible)} ${visible.length === 1 ? "is" : "are"} still unfilled`
        : `it still shows the review banner (data-rs-slot-group="${REVIEW_BANNER_GROUP}"), which says nobody has reviewed it`;
    problems.push({
      index: at < 0 ? 0 : at,
      message:
        `is a legal page that contradicts itself: ${list(filled)} ${filled.length === 1 ? "has" : "have"} ` +
        `been filled in while ${stillThere}. Those markers stand for four facts nobody has supplied -- who ` +
        `is publishing, under which law, at which address, and as of when -- and a policy that answers some ` +
        `of them while still announcing that it has not been reviewed is the confidently wrong document ` +
        `this rule exists to stop reaching a client's customers. A placeholder moved into an HTML COMMENT ` +
        `counts as filled: the reader cannot see it. Either restore the marker, or finish the page ` +
        `properly -- fill all four after legal review and delete the banner element.`,
    });
  }

  return problems;
}
