#!/usr/bin/env node
// Guard the ARTIFACT, not the source.
//
// Every rule here is a property of the bytes that are about to be uploaded, so
// this is the only place they can be enforced with certainty. Checking the repo
// source instead would pass a build step that injects a CDN tag and still ship
// it. Runs after the Tailwind compile and the meta injection, and before the
// Pages project is touched -- a site that fails these must fail before anything
// is live, not after.
//
// Rules (ARCHITECTURE.md section 1, CLAUDE.md hard rules 2 and 3):
//   1. no cdn.tailwindcss.com anywhere in the artifact
//   2. every HTML page carries <meta name="source-repo"> for THIS repo
//   3. styles.css exists and is not zero bytes
//   4. no stylesheet or script loaded from a host other than the site's own
//      origin. This is the general form of rule 1, and it is the one that keeps
//      holding when somebody adds a different CDN next year.
//   5. nothing in the built CSS or a shipped SVG FETCHES from another origin --
//      `@import`, `url()`, or an SVG href/xlink:href/src.
//   6. no Cloudflare Pages control file (`_worker.js`, `_routes.json`,
//      `_headers`, `_redirects`) at the root of the artifact. See
//      PAGES_CONTROL_FILES below; one of them can forge this publisher's own
//      gate proof.
//   7. every entry in the artifact is a REGULAR FILE. A symbolic link is read,
//      written and uploaded by three different processes at three different
//      moments, and a symlinked DIRECTORY is not walked into at all -- so every
//      rule above it silently applies to nothing (issue #141, _lib/walk.mjs).
//   8. no legal page contradicts itself: a privacy policy that still declares
//      itself unreviewed while some of the facts its placeholders stand in for
//      have been filled in (issue #147, _lib/legal.mjs). That module carries the
//      argument for why THAT is the line, rather than "any legal page in any
//      state", and why the answer is to fail the publish rather than warn.
//   9. no inline event handler, and no URL that carries its own payload, on any
//      page in the artifact (issue #166, _lib/scripting.mjs). The edit guard in
//      core/ refuses both, and it only ever sees an edit made through the panel
//      -- a hand edit reaches this runner with nothing having looked at it.
//
// Rule 9 is NOT "no JavaScript", and the distinction is the whole of #166. A
// published Rocket Site is static files with no server behind it, and
// client-side script in a visitor's browser needs no server: the templates ship
// a same-origin `behaviours.js` and switch each behaviour on with a slot, so a
// local `<script src>` is an ordinary part of a correct site and passes. What
// fails is the executable form that has no legitimate use in a template-shipped
// behaviour, and that is where the obfuscated payloads live.
//
// Rule 5 exists because rules 1 and 4 between them could not see a remote
// `@import` in a template's `tailwind.css`: the Tailwind CLI inlines the
// directive's own source but a plain `@import url(https://…)` is preserved into
// the compiled `styles.css`, which is a file rule 4 never inspects (it reads
// HTML tags) and rule 1 only greps for one literal CDN hostname. So a client's
// live site could load a font, an icon set or an entire stylesheet from a third
// party, past every check here (found by the templates work on #42).
//
// It is anchored to FETCHING SYNTAX rather than to "any absolute URL", and that
// distinction is load-bearing in both directions: an `<a href="https://…">` in
// the body is a link an agency meant to write, and `https://example.com/` in a
// `rel="canonical"` is a placeholder the publisher rewrites a step later
// (stamp-site-url). Neither fetches anything at render time, and failing them
// here would either break real sites or fight another guard.

import fs from "node:fs";
import path from "node:path";
import { createLogger, readExplicit } from "../_lib/io.mjs";
import { walkArtifact, reportRefusals } from "../_lib/walk.mjs";
import { declaredSourceRepo, attrNamePattern, attrMatches } from "../_lib/html.mjs";
import { legalPageProblems } from "../_lib/legal.mjs";
import { scriptingProblems } from "../_lib/scripting.mjs";

const TAILWIND_CDN = "cdn.tailwindcss.com";

/**
 * Rule 6: the Cloudflare Pages control files, which Pages honours from the ROOT
 * of the uploaded directory (issue #121).
 *
 * These are not assets. They are configuration of the serving edge, expressed as
 * files, and until #121 the publisher copied all four out of a client's site
 * repo without exclusion, without a guard, and without mentioning them anywhere.
 *
 *   _worker.js    turns the project into a Worker-backed site. Arbitrary
 *                 server-side code in front of a client's marketing site --
 *                 the mechanism ARCHITECTURE.md rules out at length when it
 *                 explains why robots.txt cannot vary per host.
 *   _routes.json  decides which paths that Worker sees.
 *   _headers      adds or strips security headers on every response.
 *   _redirects    points the client's traffic anywhere. And one line of it,
 *                 `/*  /cdn-cgi/access/login/anything  302`, made an entirely
 *                 ungated project answer the shape the gated proof read as the
 *                 Cloudflare Access login: the publisher asking the site whether
 *                 it was gated.
 *
 * The rsync deny-list in action.yml already keeps them out of the artifact. This
 * is the backstop, and it belongs here for the same reason every other rule in
 * this file does: it is a property of the BYTES, so a build step that writes one
 * cannot slip past a check on the source.
 *
 * ROOT ONLY. `assets/_headers` is a file with a name; Pages does not read it.
 */
export const PAGES_CONTROL_FILES = Object.freeze({
  "_worker.js":
    "turns this Pages project into a Worker-backed site, which puts arbitrary server-side code in " +
    "front of a client's marketing site. A Rocket Site is static files with nothing behind them",
  "_routes.json": "configures which paths a Pages Function sees, and a Rocket Site has no Pages Function",
  "_headers": "rewrites the HTTP headers Cloudflare serves this site with, including its security headers",
  "_redirects":
    "rewrites where every path on this site sends a visitor. One line of it can also forge the " +
    "publisher's own gate proof, by answering a redirect to /cdn-cgi/access/login from a site with no " +
    "Cloudflare Access in front of it",
});

/**
 * ANALYTICS AND MARKETING TAGS (issue #116).
 *
 * Rule 4 already refuses these, and it is right to: a third-party script on a
 * client's live marketing site is that client's outage when the third party has
 * one, and their consent problem for as long as it is there. What was wrong was
 * the SENTENCE. An agency adding Google Analytics was told to "vendor the asset
 * into the repo", which is not advice about an analytics tag, it is advice about
 * a font -- so the only supported answer was discoverable by reading
 * CONVENTIONS.md, and the observable behaviour was a failed publish with no
 * alternative named.
 *
 * There is an answer, and it costs an agency nothing in this repository:
 * **Cloudflare Web Analytics, enabled on the Pages project in the agency's own
 * Cloudflare account.** The beacon is injected at the edge, so it never enters
 * these bytes, no guard has to move, there is no cookie and therefore no consent
 * banner. It is the one measurement route that does not put a Rocket Lab
 * component or a third party in front of a client's site.
 *
 * What stays refused, and is refused here rather than argued about per client: a
 * conversion pixel, and a tag manager. A tag manager in particular is a channel
 * for loading arbitrary code onto a client's site later, from a dashboard, with
 * no commit and no review -- which is every property this guard exists to
 * remove, shipped as a feature. ARCHITECTURE.md, "Analytics", carries the
 * decision and the non-goal that goes with it.
 *
 * This list decides only WHICH SENTENCE a failure gets. Every foreign script
 * fails either way, so a host missing from it costs a worse message and never a
 * published tag.
 */
export const MEASUREMENT_HOSTS = Object.freeze([
  "googletagmanager.com",
  "google-analytics.com",
  "googleadservices.com",
  "connect.facebook.net",
  "snap.licdn.com",
  "analytics.tiktok.com",
  "hotjar.com",
  "clarity.ms",
  "plausible.io",
  "usefathom.com",
  "matomo.cloud",
  "segment.com",
  "hs-scripts.com",
]);

/** Does this URL point at something whose whole job is measurement? */
export function isMeasurementUrl(url) {
  const host = /^(?:https?:)?\/\/([^/?#]+)/i.exec(String(url).trim())?.[1]?.toLowerCase() ?? "";
  return MEASUREMENT_HOSTS.some((h) => host === h || host.endsWith(`.${h}`));
}

/** The remedy sentence a foreign subresource gets, which depends on what it is. */
export function remedyFor(url) {
  if (!isMeasurementUrl(url)) return `Vendor the asset into the repo instead.`;
  return (
    `That is an analytics or marketing tag, and a Rocket Site cannot carry one: it is static files with ` +
    `nothing behind them, and a third-party script is the client's outage when that third party has one. ` +
    `THERE IS A SUPPORTED WAY TO GIVE THE CLIENT NUMBERS: turn on Cloudflare Web Analytics for this Pages ` +
    `project in the agency's own Cloudflare account. The beacon is injected at the edge, so it never enters ` +
    `these bytes, nothing in the repo changes, and it sets no cookie -- which is also why it needs no consent ` +
    `banner. See docs/onboarding.md, "Analytics". Conversion pixels and tag managers stay refused: a tag ` +
    `manager loads whatever it is told to load, later, from a dashboard, with no commit and no review.`
  );
}

export function lineOf(content, index) {
  return content.slice(0, index).split("\n").length;
}

const TEXTUAL = /\.(html?|css|js|mjs|json|svg|txt|xml)$/i;

/** Absolute or protocol-relative: anything that leaves this site's origin. */
export function isForeignOrigin(url) {
  return /^(https?:)?\/\//i.test(String(url).trim());
}

/**
 * A `<link>` or `<script>` opening tag, however its values are quoted.
 *
 * `[^>]*` was wrong for the same reason the reads below were (issue #219,
 * reopened): a `>` inside an attribute VALUE ended the tag early, so
 * `<link rel="stylesheet" data-x="a>b" href="https://cdn.example/x.css">` was
 * read as a tag ending at the `>` in `data-x` and its real `href` was never in
 * the text this function looked at. Anchoring the attribute reads without this
 * would leave the fix bypassable by the same move it exists to stop: write the
 * decoy first, and put a `>` in it.
 *
 * Deliberately permissive about what an attribute looks like. This is a
 * PROHIBITION, and a finder that refuses to recognise a malformed tag hands the
 * browser a subresource no rule below ever saw. Over-matching here costs a
 * failed publish that names a real tag; under-matching ships one.
 */
const SUBRESOURCE_TAG_RE = /<(link|script)\b((?:"[^"]*"|'[^']*'|[^>])*)>/gi;

const ATTR_VALUE_RE = (name) =>
  new RegExp(`${attrNamePattern(name)}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]*))`, "gi");

const REL_RE = ATTR_VALUE_RE("rel");
const HREF_RE = ATTR_VALUE_RE("href");
const SRC_RE = ATTR_VALUE_RE("src");

/**
 * One attribute of one tag, as a browser reads it: the FIRST occurrence of the
 * name at a NAME POSITION, in any of the three quoting forms.
 *
 * Empty string when the tag does not carry it, because every caller below asks
 * "is this value foreign" and an absent attribute is not.
 */
function attrValue(tagText, re) {
  for (const m of attrMatches(tagText, re)) return m[1] ?? m[2] ?? m[3] ?? "";
  return "";
}

/**
 * Rule 4: a stylesheet or a script loaded from somewhere that is not this site.
 *
 * ANCHORED TO A NAME POSITION, and reading all three quoting forms (issue #219,
 * reopened 2026-08-17). All three reads here used to be of the shape
 * `/href=["']([^"']*)["']/i`, which is not a word break wrongly used as an
 * attribute boundary -- it is no boundary at all, which is worse, and it FAILED
 * OPEN. Measured against the shipped function before this fix:
 *
 *   MISSED  <link rel="stylesheet" data-href="/local.css" href="https://evil.example/x.css">
 *   CAUGHT  <link rel="stylesheet" href="https://evil.example/x.css">          <- the control
 *   MISSED  <script data-src="/local.js" src="https://evil.example/x.js"></script>
 *   MISSED  <link data-rel="icon" rel="stylesheet" href="https://evil.example/x.css">
 *
 * A leftmost `data-href` won and the real attribute was never read, so a page
 * carrying a decoy shipped a third-party stylesheet or script onto a client's
 * live site past the guard whose whole job is to refuse one. That is `CLAUDE.md`
 * hard rule 2 and this file's own model that the published bytes are the whole
 * site.
 *
 * `rel` is the third one and it is the worst of them: the decoy does not
 * redirect the read to a harmless value, it makes the tag look like something
 * other than a stylesheet, so the link is skipped entirely and the `href` is
 * never even reached.
 *
 * Two more shapes were fail-open here and are fixed with it, because leaving
 * them would make the anchoring decorative -- a decoy is only ever written by
 * somebody who will write the next-cheapest one:
 *
 *   - an UNQUOTED value (`<script src=https://evil.example/x.js>`) was invisible
 *     to a read that required quotes, while the browser fetches it. That is
 *     issue #125's lesson in this function: the parsers disagreed about what an
 *     attribute is, and the browser's answer is the one that ships.
 *   - a `>` inside another attribute's value truncated the tag. See
 *     SUBRESOURCE_TAG_RE.
 *
 * `attrMatches` walks the tag's quote state as well as anchoring the name,
 * because `data-note=" href='x'"` offers a name-shaped match preceded by a
 * space -- and it is the leftmost one, which no assertion over the preceding
 * character can see.
 */
export function findExternalAssets(html) {
  const hits = [];
  for (const m of String(html).matchAll(SUBRESOURCE_TAG_RE)) {
    const tag = m[0];
    const kind = m[1].toLowerCase();
    if (kind === "link") {
      // `\b` over the VALUE, deliberately, and it is not the family this fix is
      // about: `rel` is a space-separated token list, so over-matching it means
      // more links get their href checked, which fails closed.
      if (!/\bstylesheet\b/i.test(attrValue(tag, REL_RE))) continue;
      const href = attrValue(tag, HREF_RE);
      if (isForeignOrigin(href)) hits.push({ index: m.index, kind: "stylesheet", url: href });
    } else {
      const src = attrValue(tag, SRC_RE);
      if (src && isForeignOrigin(src)) hits.push({ index: m.index, kind: "script", url: src });
    }
  }
  return hits;
}

/**
 * THE definition of "this fetches something at render time", used for every
 * non-HTML-tag surface in the artifact. One definition, so a new file type is a
 * one-line addition rather than a fourth opinion about what a URL is.
 *
 *   @import  a stylesheet pulling in another stylesheet, in either spelling
 *   url()    fonts, background images, masks, cursors -- CSS and inline styles
 *   href / xlink:href / src   SVG's own fetching attributes (<image>, <use>,
 *            <feImage>), which are how an icon sprite ends up loading from a CDN
 *
 * Deliberately NOT included: an HTML `<a href>`, and any absolute URL in a meta
 * or link tag that only DECLARES an address (canonical, og:url, og:image is a
 * declaration a crawler resolves later, not a fetch the browser performs while
 * rendering the page). Those are somebody else's rules.
 *
 * `svg-href` USED TO ANCHOR THE NAME WITH `\b`, and was free-listed out of the
 * publisher-wide census on the reason that it is *a prohibition, so over-matching
 * fails closed* (issue #219, `7fef794`). That reason was re-examined when #219
 * was reopened and it does not survive, for three reasons:
 *
 *   1. It is true of the miss direction and silent about the harm. Over-matching
 *      here does not ship anything; it BLOCKS a publish with a diagnostic saying
 *      an SVG "fetches from another origin at render time: svg-href https://..."
 *      about a `data-href`, which fetches nothing. `7fef794` itself classified
 *      exactly that harm as a defect one directory over, in guard-site-url's
 *      duplicate count: a blocked deploy with a diagnostic the agency can
 *      disprove by reading the tag is worse than no diagnostic. The same harm
 *      cannot be a defect there and acceptable here.
 *   2. The exemption was FILE-scoped, so it read as "the occurrences in
 *      guard-artifact.mjs have been considered and are safe". They had not:
 *      findExternalAssets, in the same file, anchored nothing at all and failed
 *      OPEN. The census could never have caught it -- it hunts `\b` -- but the
 *      free-list entry is what made the file look examined.
 *   3. `\b` is not what was catching a namespaced attribute anyway; it was only
 *      reaching one by accident, exactly as URL_ATTR_RE was until #219 DECLARED
 *      `xlink:href`. So the anchor now allows an explicit XML namespace prefix
 *      rather than any character that happens to be non-word: `xlink:href` and
 *      `xl:href` (any prefix bound to the xlink namespace) still match, and
 *      `data-href` no longer does. Narrowing without that would have been the
 *      real regression the free-list entry was afraid of.
 */
const FETCHING_SYNTAX = [
  { kind: "@import", re: /@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)/gi, groups: [2, 4] },
  { kind: "url()", re: /url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, groups: [2] },
  {
    kind: "svg-href",
    re: new RegExp(
      `${attrNamePattern("(?:[A-Za-z_][\\w.]*:)?href|src")}\\s*=\\s*(['"])([^'"]+)\\1`,
      "gi"
    ),
    groups: [2],
  },
];

/** Which fetching rules apply to a file, by extension. */
export function fetchingRulesFor(file) {
  if (/\.css$/i.test(file)) return ["@import", "url()"];
  if (/\.svg$/i.test(file)) return ["@import", "url()", "svg-href"];
  // Inline <style> blocks and style="" attributes fetch exactly like a
  // stylesheet does. HTML tag attributes are covered by findExternalAssets.
  if (/\.html?$/i.test(file)) return ["@import", "url()"];
  return [];
}

export function findForeignFetches(text, kinds) {
  const hits = [];
  for (const rule of FETCHING_SYNTAX) {
    if (!kinds.includes(rule.kind)) continue;
    for (const m of String(text).matchAll(rule.re)) {
      const url = rule.groups.map((g) => m[g]).find((v) => v !== undefined) ?? "";
      if (isForeignOrigin(url)) hits.push({ index: m.index, kind: rule.kind, url: url.trim() });
    }
  }
  return hits.sort((a, b) => a.index - b.index);
}

/**
 * What this page tells a BROWSER about which repo backs it (issues #138, #125).
 *
 * This used to be the first quoted match, which is three different mistakes at
 * once: a tag inside a comment counted, an unquoted tag did not, and where a
 * page carried two the answer was decided by document order. A page could
 * therefore declare one repo here and another one to the extension, which is
 * hard rule 3's entire mechanism pointing at somebody else's repository.
 *
 * Returns `{ tags, repo, disagrees }` -- the count matters as much as the value,
 * because "exactly one" is the property that survives a parser being wrong
 * somewhere else.
 */
export function declaredRepo(html) {
  return declaredSourceRepo(html);
}

export function runGuardArtifact({ env, logger }) {
  const dir = readExplicit(env, "PUBLISH_DIR");
  const repo = readExplicit(env, "REPO").trim();
  let failures = 0;
  const fail = (file, line, msg) => {
    failures += 1;
    logger.errorAt(path.relative(dir, file) || file, line, msg);
  };

  if (!fs.existsSync(dir)) {
    logger.error(`Publish directory '${dir}' does not exist -- there is nothing to upload.`);
    return 1;
  }

  // ── 7. every entry is a regular file (issue #141) ─────────────────────
  // First, because it decides what the rest of this guard is even able to see: a
  // symlinked directory is one entry with an unrecognised extension, so nothing
  // beneath it is walked, read or checked by any rule below -- while the upload
  // follows the link and serves all of it.
  const { files: regular, refused } = walkArtifact(dir);
  reportRefusals(refused, fail);

  // ── 3. styles.css ─────────────────────────────────────────────────────
  const stylesPath = path.join(dir, "styles.css");
  if (!fs.existsSync(stylesPath)) {
    logger.error(
      `No styles.css in the artifact. Tailwind is compiled by the publisher and the published site ` +
        `must not fall back to a CDN. Refusing to publish an unstyled client site.`
    );
    failures += 1;
  } else if (fs.statSync(stylesPath).size === 0) {
    logger.error(
      `styles.css is zero bytes -- the Tailwind build produced nothing. Refusing to publish an ` +
        `unstyled client site.`
    );
    failures += 1;
  }

  // ── 6. Cloudflare Pages control files at the artifact root ────────────
  for (const [name, why] of Object.entries(PAGES_CONTROL_FILES)) {
    if (!fs.existsSync(path.join(dir, name))) continue;
    fail(
      path.join(dir, name),
      1,
      `is a Cloudflare Pages control file and must never be published. Pages reads it from the root of ` +
        `the uploaded directory, where it ${why}. It is excluded from the upload directory by the ` +
        `publisher, so finding one here means it arrived some other way. Delete it from the site repo.`
    );
  }

  // ── 1. Tailwind CDN, anywhere in the artifact ─────────────────────────
  for (const file of regular) {
    if (!TEXTUAL.test(file)) continue;
    const content = fs.readFileSync(file, "utf8");
    let at = content.indexOf(TAILWIND_CDN);
    while (at !== -1) {
      fail(
        file,
        lineOf(content, at),
        `references ${TAILWIND_CDN}. The CDN build has no purge step, causes a flash of unstyled ` +
          `content, and puts a third-party runtime dependency on a client's live site -- an outage ` +
          `or a hijack there defaces every site this agency has published. Tailwind is compiled to ` +
          `styles.css by this workflow; remove the CDN tag.`
      );
      at = content.indexOf(TAILWIND_CDN, at + 1);
    }

    // ── 5. anything that FETCHES from another origin ───────────────────
    // The compiled styles.css is the file this catches in practice: a remote
    // @import in a template's tailwind.css survives the Tailwind build and
    // reaches a client's live site, and no HTML-tag check can see it.
    const kinds = fetchingRulesFor(file);
    if (kinds.length > 0) {
      for (const hit of findForeignFetches(content, kinds)) {
        fail(
          file,
          lineOf(content, hit.index),
          `fetches from another origin at render time: ${hit.kind} ${hit.url}. A client's live ` +
            `marketing site must not depend on a third-party host to draw itself -- an outage there ` +
            `is a broken page for the client's customers, and a compromise there is arbitrary CSS or ` +
            `SVG on their domain. This one is invisible to the HTML checks because it lives in the ` +
            `compiled CSS or in an asset. Vendor the file into the repo and reference it by a ` +
            `site-relative path.`
        );
      }
    }
  }

  // ── 2 and 4. Per-page checks ──────────────────────────────────────────
  const pages = regular.filter((f) => /\.html?$/i.test(f));
  if (pages.length === 0) {
    logger.error(`No HTML pages in '${dir}' -- there is no site to publish.`);
    failures += 1;
  }
  for (const file of pages) {
    const content = fs.readFileSync(file, "utf8");

    const declared = declaredRepo(content);
    if (declared.tags.length === 0) {
      fail(
        file,
        1,
        `has no <meta name="source-repo">. That tag is the only mechanism the extension has for ` +
          `resolving a live page back to its repo, and the publisher injects it -- if it is missing ` +
          `here, the injection step did not see this file. A tag inside an HTML COMMENT is not a tag: ` +
          `it is invisible to the browser, to the extension, and to the public post-deploy proof.`
      );
    } else if (declared.disagrees) {
      // Count before value (issue #138). A page carrying two tags cannot say
      // which repo backs it, and every reader that picks one is picking by
      // document order -- which is how a page declared one repo to this guard
      // and another to the browser.
      fail(
        file,
        lineOf(content, declared.tags[1].start),
        `carries ${declared.tags.length} <meta name="source-repo"> tags, naming ` +
          `${declared.tags.map((t) => `'${t.content}'`).join(" and ")}. A page carries exactly one. ` +
          `Which of them wins is decided by document order in some readers and by the browser's parser ` +
          `in others, so this page would resolve to different repositories in the artifact guard, in ` +
          `the post-deploy proof and in the extension -- and the extension's answer is the one that ` +
          `decides where an edit is committed. Remove the one this site did not write.`
      );
    } else if (declared.repo.toLowerCase() !== repo.toLowerCase()) {
      fail(
        file,
        lineOf(content, declared.tags[0].start),
        `declares source-repo '${declared.repo}' but is being published from '${repo}'. The extension ` +
          `would send this page's edits to the wrong repo.`
      );
    }

    for (const hit of findExternalAssets(content)) {
      fail(
        file,
        lineOf(content, hit.index),
        `loads a ${hit.kind} from another origin (${hit.url}). A client's live marketing site must ` +
          `not depend on a third-party host at runtime: an outage or a compromise there breaks or ` +
          `defaces the site. ${remedyFor(hit.url)}`
      );
    }

    // ── 8. the legal rule, on the artifact (issue #147) ─────────────────
    // The runtime guard in core/ and templates/validate.mjs both enforce
    // CLAUDE.md hard rule 4, and neither of them runs in a client's repository:
    // a hand edit, another tool, or a template updated in a repo that has since
    // diverged reaches the public with nothing objecting. _lib/legal.mjs holds
    // the vendored data and the argument for what it does and does not refuse.
    for (const problem of legalPageProblems(path.relative(dir, file), content)) {
      fail(file, lineOf(content, problem.index), problem.message);
    }

    // ── 9. the scripting rule, on the artifact (issue #166) ────────────
    // The same rule core/src/lib/content-safety.ts applies to a proposal, on
    // the bytes instead, because the proposal guard never sees a hand edit.
    // _lib/scripting.mjs holds the vendored data and the argument for the one
    // place the two deliberately differ.
    for (const problem of scriptingProblems(content)) {
      fail(file, lineOf(content, problem.index), problem.message);
    }
  }

  if (failures > 0) {
    logger.error(
      `Artifact guard failed with ${failures} problem(s). Nothing was uploaded and the Cloudflare ` +
        `Pages project was not touched.`
    );
    return 1;
  }
  logger.info(`Artifact guard passed: ${pages.length} page(s), styles.css present, no foreign origins.`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(runGuardArtifact({ env: process.env, logger }));
}
