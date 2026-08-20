#!/usr/bin/env node
// The artifact guard for what a page says about its own address.
//
// Runs immediately after stamp-site-url.mjs and over the same bytes, and it is
// deliberately a SEPARATE check rather than a rule inside that script: a
// rewriter that verifies its own work only proves it did what it thinks it did.
// This one re-reads the artifact from disk and knows nothing about which files
// the rewriter visited, so a placeholder in a stylesheet, a JSON blob, an inline
// script or a page the rewriter never opened still fails the publish.
//
// Rules:
//   1. No absolute URL on the placeholder host survives ANYWHERE in the
//      artifact. Matched as a host, so `mailto:hello@example.com` -- a contact
//      placeholder for the client to fill -- is untouched.
//   2. Every page's canonical is exactly this page's own URL on the serving
//      origin. A canonical on any other host fails, whether it is a leftover
//      placeholder or a hand-edit.
//   3. og:url, where present, matches the canonical.
//   4. Every indexable page HAS a canonical. Absence means the stamper never
//      saw the file, which is the failure mode a guard exists to catch.
//
// This step is fatal before the upload, so the artifact that reaches a client's
// visitors is never one that tells search engines to prefer somebody else's
// domain.

import fs from "node:fs";
import path from "node:path";

import { createLogger, readExplicit } from "../_lib/io.mjs";
import { walkArtifact, reportRefusals } from "../_lib/walk.mjs";
import { liveMatches, tagAttr, attrNamePattern, attrMatches } from "../_lib/html.mjs";
import { lineOf } from "../build-site/guard-artifact.mjs";
import { PLACEHOLDER_URL_RE, NOT_INDEXABLE, pageUrlPath } from "./stamp-site-url.mjs";

const TEXTUAL = /\.(html?|css|js|mjs|json|svg|txt|xml)$/i;

/**
 * The canonical this page declares TO A BROWSER, and where it says it.
 *
 * Live markup only (issue #138). Taking the first textual match meant a stale
 * `<!-- <link rel="canonical" href="..."> -->` above the real one was the tag
 * this guard judged the page on -- the same first-textual-match mistake that let
 * a page declare one repo here and another in the DOM. Returns null when the
 * page has none.
 *
 * `rel` is anchored by `attrNamePattern` and not by `\b` (issue #219): a word
 * break is not an attribute boundary, so `\brel` asserts inside `data-rel` and a
 * decoy `<link data-rel="canonical">` ahead of the real tag was the one this
 * guard judged the page on -- the same first-match mistake as the comment case
 * above, one attribute lower down.
 */
const CANONICAL_TAG_RE = new RegExp(
  `<link\\b[^>]*${attrNamePattern("rel")}\\s*=\\s*["']canonical["'][^>]*>`,
  "i"
);
const OG_URL_TAG_RE = new RegExp(
  `<meta\\b[^>]*${attrNamePattern("property")}\\s*=\\s*["']og:url["'][^>]*>`,
  "i"
);

export function canonicalTag(html) {
  return liveMatches(html, CANONICAL_TAG_RE)[0] ?? null;
}

export function canonicalHref(html) {
  const tag = canonicalTag(html);
  if (!tag) return null;
  // The FIRST href in any quoting form, because that is the one the browser
  // keeps. Reading the last quoted one is what let an appended duplicate satisfy
  // this guard while the page declared a different address (issue #139).
  return tagAttr(tag.text, "href")?.trim() ?? "";
}

export function ogUrlTag(html) {
  return liveMatches(html, OG_URL_TAG_RE)[0] ?? null;
}

export function ogUrlContent(html) {
  const tag = ogUrlTag(html);
  if (!tag) return null;
  return tagAttr(tag.text, "content")?.trim() ?? "";
}

export function runGuardSiteUrl({ env, logger }) {
  const dir = readExplicit(env, "PUBLISH_DIR");
  const origin = readExplicit(env, "SITE_ORIGIN").trim();
  let failures = 0;
  const fail = (file, line, msg) => {
    failures += 1;
    logger.errorAt(path.relative(dir, file) || file, line, msg);
  };

  // An empty origin would silently turn every rule below into a no-op, which is
  // the way a guard stops guarding without anyone noticing. Fail instead.
  if (!origin || !/^https:\/\/[^/\s]+$/.test(origin)) {
    logger.error(
      `The site URL guard was handed SITE_ORIGIN='${origin}', which is not an https origin. That value ` +
        `comes from the stamping step, so this means the canonical URL of every published page is ` +
        `unverified. Refusing to publish rather than running a check that cannot fail.`
    );
    return 1;
  }
  if (!fs.existsSync(dir)) {
    logger.error(`Publish directory '${dir}' does not exist -- there is nothing to check.`);
    return 1;
  }

  // ── 0. every entry is a regular file (issue #141) ─────────────────────
  // This guard re-reads the artifact from disk in its own process, which is the
  // whole reason it exists -- and reading through a symbolic link means it reads
  // a file that is not in the artifact at all, then reports on the artifact.
  const { files: regular, refused } = walkArtifact(dir);
  reportRefusals(refused, fail);

  // ── 1. no placeholder host anywhere in the artifact ───────────────────
  for (const file of regular) {
    if (!TEXTUAL.test(file)) continue;
    const content = fs.readFileSync(file, "utf8");
    for (const m of content.matchAll(PLACEHOLDER_URL_RE)) {
      fail(
        file,
        lineOf(content, m.index),
        `still carries the placeholder URL '${m[0]}' after the publisher rewrote this site's own ` +
          `address to ${origin}. A published page pointing at example.com is not a cosmetic defect: ` +
          `in a canonical it asks search engines to drop the client's page in favour of a domain the ` +
          `agency does not own, and in an og:image it renders a broken preview everywhere the link ` +
          `is shared. The rewrite covers canonical, og:url and absolute URLs in attributes -- a hit ` +
          `here is one somewhere it does not reach, such as inline script or CSS. Remove it from the ` +
          `site source.`
      );
    }
  }

  // ── 2-4. what each page claims about itself ───────────────────────────
  for (const file of regular.filter((f) => /\.html?$/i.test(f))) {
    const rel = path.relative(dir, file).split(path.sep).join("/");
    const content = fs.readFileSync(file, "utf8");
    const expected = origin + pageUrlPath(rel);
    const indexable = !NOT_INDEXABLE.has(rel);

    // A duplicate attribute is DROPPED by the browser, so the value this guard
    // reads and the value the page declares are different ones (issue #139).
    // Checked before the value, because comparing the wrong attribute against
    // the right answer is how a broken canonical passed green.
    //
    // COUNTED BY NAME POSITION, not by word break (issue #219). `\bhref\s*=`
    // counts `data-href` and `xlink:href` as occurrences of `href`, so this
    // reported "carries href twice" about a tag carrying it exactly once -- a
    // blocked deploy with a diagnostic the agency can disprove by reading the
    // tag, which is worse than no diagnostic. `attrMatches` also throws away a
    // name-shaped string sitting inside another attribute's quoted value, which
    // no assertion over the preceding character can see.
    for (const [tag, attr, what] of [
      [canonicalTag(content), "href", 'the canonical <link>'],
      [ogUrlTag(content), "content", "the og:url <meta>"],
    ]) {
      if (!tag) continue;
      const re = new RegExp(`${attrNamePattern(attr)}\\s*=`, "gi");
      const count = [...attrMatches(tag.text, re)].length;
      if (count <= 1) continue;
      fail(
        file,
        lineOf(content, tag.index),
        `carries ${attr} twice on ${what}: ${tag.text}. An HTML parser keeps the FIRST duplicate ` +
          `attribute and drops the rest, so the address this page actually declares to a crawler is ` +
          `not the one a checker reading the last value would see. One attribute, one value.`
      );
    }

    const canonical = canonicalHref(content);
    if (canonical === null) {
      if (indexable) {
        fail(
          file,
          1,
          `has no <link rel="canonical">. The publisher stamps one into every indexable page, so its ` +
            `absence means the stamping step never opened this file and nothing here can be trusted ` +
            `to name the right host.`
        );
      }
    } else if (canonical !== expected) {
      fail(
        file,
        lineOf(content, canonicalTag(content)?.index ?? 0),
        `declares canonical '${canonical}' but this page is published at '${expected}'. A canonical ` +
          `on any host other than the site's own asks every crawler to prefer that host's copy, and ` +
          `a canonical on the wrong PATH of the right host collapses two pages into one in the index.`
      );
    }

    const ogUrl = ogUrlContent(content);
    if (ogUrl !== null && ogUrl !== expected) {
      fail(
        file,
        lineOf(content, ogUrlTag(content)?.index ?? 0),
        `declares og:url '${ogUrl}' but this page is published at '${expected}'. Every link to this ` +
          `page shared on Slack, LinkedIn or iMessage would render the wrong address.`
      );
    }
  }

  if (failures > 0) {
    logger.error(
      `Site URL guard failed with ${failures} problem(s). Nothing was uploaded; the Cloudflare Pages ` +
        `project exists but still serves whatever it served before this run.`
    );
    return 1;
  }
  logger.info(`Site URL guard passed: every page's canonical names ${origin} and no placeholder URL survived.`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(runGuardSiteUrl({ env: process.env, logger }));
}
