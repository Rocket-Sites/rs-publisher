#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════
// Stamp the site's OWN URL into every published page, and emit the two files a
// marketing site is judged by: robots.txt and sitemap.xml.
//
// The argument is the same one that put inject-source-meta.mjs in this pipeline:
// the URL a site is served at is a DEPLOY-TIME FACT, and the template is the
// wrong place to assert it. So the templates keep `https://example.com/` as an
// obvious placeholder and the publisher -- the only party that knows the answer
// -- rewrites it into the real serving origin. The published bytes are always
// right rather than merely checked, and guard-site-url.mjs beside this file
// fails the run if any placeholder survived.
//
// What a wrong canonical costs, precisely: it does not degrade the client's
// search result, it ASKS EVERY CRAWLER TO DROP THE PAGE in favour of a domain
// the agency does not own. A missing canonical is a missed optimisation; a
// canonical on example.com is an instruction to de-index. The og: pair is the
// visible version of the same failure -- a link shared to the client on Slack
// renders a broken image and somebody else's URL.
//
// ── Why this step runs AFTER the Pages project exists ─────────────────────
//
// Everything else in build-site runs before Cloudflare is touched, deliberately.
// This cannot: the canonical host is the project's real .subdomain (or an
// attached custom domain), and on a first deploy neither exists until
// ensure-project has run. The alternatives were worse. Guessing
// `<project>.pages.dev` is exactly the guess domain.mjs exists to refuse -- on a
// global pages.dev name collision that host belongs to a DIFFERENT Cloudflare
// account, so the guess would point a client's canonical at a stranger's
// website. Stamping nothing on a first deploy would ship every new site without
// a canonical, an og:image or a sitemap until somebody happened to push again.
// So the step is placed where the fact is known and still before a single byte
// is uploaded, which is the property that actually matters.
//
// ── The pages.dev twin (issue #39 item 5, decided) ────────────────────────
//
// Once a custom domain is attached, the same content answers on two hostnames
// and they compete as duplicates. The fix is the CROSS-HOST CANONICAL, which is
// what this step writes: both hosts serve pages whose canonical names the custom
// domain, which is exactly the signal search engines are documented to follow.
// The pages.dev twin is NOT disallowed in robots.txt, and it deliberately cannot
// be: robots.txt is one static file in one artifact served identically on every
// host, so a `Disallow: /` aimed at the twin would de-index the client's real
// site with it. Serving a different robots.txt per host needs a Pages Function,
// and a Rocket Site has no backend (CLAUDE.md hard rule 1).
// ═══════════════════════════════════════════════════════════════════════

import fs from "node:fs";
import path from "node:path";

import { createLogger, createOutputs, readExplicit } from "../_lib/io.mjs";
import { createCloudflare } from "../_lib/cf.mjs";
import { resolveDomain, reconcileCustomDomains } from "../_lib/domain.mjs";
import { isValidMode, MODES } from "../_lib/validate.mjs";
import { walkArtifact, reportRefusals } from "../_lib/walk.mjs";
import { headInsertionPoint, replaceLive, attrNamePattern, attrMatches } from "../_lib/html.mjs";

/**
 * The placeholder every template ships. Matched as a URL HOST, never as a bare
 * string: `mailto:hello@example.com` is a contact placeholder a client fills in
 * and is none of this step's business, while `https://example.com/` in a
 * canonical is a deploy-breaking defect. Protocol-relative `//example.com/` and
 * the `www.` form are the same defect written differently.
 */
export const PLACEHOLDER_URL_RE = /(?:https?:)?\/\/(?:www\.)?example\.com(?=[/"'\s>)]|$)/gi;

/** A page that must never be advertised to a crawler as content. */
export const NOT_INDEXABLE = new Set(["404.html"]);

/**
 * Anything that invites a crawl by listing URLs: `sitemap.xml`, but also
 * `sitemap_index.xml`, `sitemap-1.xml` and the gzipped forms, at any depth.
 * Matched by NAME because that is what a crawler recognises, and removed
 * wholesale in gated mode.
 */
export const SITEMAP_FILE_RE = /^sitemap[\w.-]*\.xml(\.gz)?$/i;

/**
 * The path a published page is actually served at.
 *
 * Cloudflare Pages redirects `/about.html` to `/about` and serves a directory's
 * index at its trailing slash, so the `.html` form is a URL that 3xxs. A
 * canonical pointing at a redirect is a canonical pointing at the wrong URL.
 */
export function pageUrlPath(relPath) {
  const parts = String(relPath).split(path.sep).join("/");
  if (parts === "index.html") return "/";
  if (parts.endsWith("/index.html")) return `/${parts.slice(0, -"index.html".length)}`;
  return `/${parts.replace(/\.html?$/i, "")}`;
}

/**
 * Set (or add) one attribute on a single tag, preserving everything else.
 *
 * ALL THREE QUOTING FORMS (issue #139). This matched only a quoted value and
 * otherwise APPENDED, so an unquoted one produced a tag carrying the attribute
 * twice:
 *
 *   in:  <link rel="canonical" href=https://example.com/old-path>
 *   out: <link rel="canonical" href=https://real.pages.dev/old-path href="https://real.pages.dev/">
 *
 * Per spec a duplicate attribute is DROPPED, so the browser's canonical was
 * `/old-path` while guard-site-url read the appended one and passed the publish.
 * That is precisely the failure the guard's own message names -- "a canonical on
 * the wrong PATH of the right host collapses two pages into one in the index" --
 * shipped green. Same for `og:url content=`.
 *
 * AND THE ATTRIBUTE THE CALLER ASKED FOR (issue #219). The name was anchored
 * with a word break, which is not an attribute boundary, so the pattern for
 * `href` asserted inside `data-href` and inside `xlink:href`. `String.replace`
 * with a non-global regex takes the LEFTMOST match, so a `data-*` or namespaced
 * attribute written before the real one was the one rewritten and the real one
 * was never touched:
 *
 *   in:  <link rel="canonical" data-href="#top" href="https://example.com/old">
 *   out: <link rel="canonical" data-href="https://real.pages.dev/about" href="https://example.com/old">
 *
 * Worse where there is no real attribute at all: the decoy made the test true,
 * so the append branch never ran and the page shipped a canonical <link> with no
 * href. Nothing here ships a `data-href` -- templates carry none -- but templates
 * are hand-editable HTML by design, and an Alpine, htmx or Turbo idiom on the
 * canonical tag is ordinary authoring.
 *
 * `attrNamePattern` decides where a name may START; `attrMatches` decides where
 * the VALUES are, because a name-shaped string inside another attribute's quoted
 * value is a decoy no assertion over the preceding character can see.
 */
export function setAttr(tag, name, value) {
  const re = new RegExp(`(${attrNamePattern(name)}\\s*=\\s*)("[^"]*"|'[^']*'|[^\\s"'>]*)`, "gi");
  for (const m of attrMatches(tag, re)) {
    return `${tag.slice(0, m.index)}${m[1]}"${value}"${tag.slice(m.index + m[0].length)}`;
  }
  const selfClosing = /\/>$/.test(tag);
  return `${tag.slice(0, selfClosing ? -2 : -1).replace(/\s*$/, "")} ${name}="${value}"${selfClosing ? " />" : ">"}`;
}

/**
 * The attributes an absolute URL can legitimately live in.
 *
 * The placeholder rewrite is scoped to these rather than applied to the whole
 * document (issue #139). It used to run over every byte of the page, so
 * `<code>https://example.com/pricing</code>` in a client's own visible copy was
 * silently edited by the publisher -- and the guard could never report it,
 * because the guard matches the same pattern over bytes the rewriter had already
 * changed. A placeholder in visible text is now left exactly as written, and
 * guard-site-url fails the publish naming the file and line, which is the
 * difference between the publisher correcting an address it owns and the
 * publisher rewriting a client's words.
 *
 * `xlink:href` is DECLARED here rather than reached by accident (issue #219). It
 * used to be matched only because the word break asserted after the colon, which
 * is the same defect that rewrote `data-href`; once the name is properly
 * anchored, an undeclared `xlink:href` would silently stop having its
 * placeholder host rewritten. It is how an SVG `<image>` addresses its file.
 */
const URL_ATTR_RE = new RegExp(
  `${attrNamePattern("xlink:href|href|src|content|action|poster|srcset|data-[\\w-]+")}` +
    `\\s*=\\s*(?:"[^"]*"|'[^']*'|[^\\s"'>]+)`,
  "gi"
);

// `rel` and `property` are attribute names too, and were anchored the same wrong
// way (issue #219): the word break asserts inside `data-rel`, so a decoy
// `<link data-rel="canonical" href="#top">` ahead of the real canonical was the
// tag this step rewrote, leaving the real one carrying the placeholder. The
// guard beside this file then failed the publish over a tag the agency will read
// and find correct.
const CANONICAL_TAG_RE = new RegExp(
  `<link\\b[^>]*${attrNamePattern("rel")}\\s*=\\s*["']canonical["'][^>]*>`,
  "gi"
);
const OG_URL_TAG_RE = new RegExp(
  `<meta\\b[^>]*${attrNamePattern("property")}\\s*=\\s*["']og:url["'][^>]*>`,
  "gi"
);

/**
 * Rewrite one page so that everything it says about its own location is true.
 *
 * REPLACES rather than fills: a canonical hand-edited to an unrelated host is
 * corrected here, exactly as a hand-edited source-repo is. Detecting it and
 * failing would leave the agency to fix bytes the publisher already knows the
 * right value for.
 */
export function rewritePage(html, { origin, pageUrl, indexable = true }) {
  // 1. Any absolute URL on the placeholder host becomes this site's own origin,
  //    IN AN ATTRIBUTE. This is what carries og:image and any hand-written
  //    absolute self-link. Visible copy is the client's, not the publisher's:
  //    a placeholder there survives to be reported by the guard.
  let out = replaceLive(html, URL_ATTR_RE, (attr) => attr.replace(PLACEHOLDER_URL_RE, origin));

  // 2. canonical and og:url are set to THIS page's URL, whatever they said.
  //    LIVE tags only (issue #138): a commented-out canonical is not this page's
  //    canonical, and rewriting one would edit a comment while the guard beside
  //    this file went on reading the first TEXTUAL match.
  let sawCanonical = false;
  out = replaceLive(out, CANONICAL_TAG_RE, (tag) => {
    sawCanonical = true;
    return setAttr(tag, "href", pageUrl);
  });
  out = replaceLive(out, OG_URL_TAG_RE, (tag) => setAttr(tag, "content", pageUrl));

  // 3. A page with no canonical at all gets one -- except 404, which must not
  //    advertise itself as the canonical anything.
  if (!sawCanonical && indexable) {
    const tag = `<link rel="canonical" href="${pageUrl}">`;
    // The same insertion point the recognition meta uses, for the same reason:
    // a `<head>` inside the leading legal-review comment two shipped templates
    // carry would otherwise take the canonical, and the page would then fail its
    // own guard with "the stamping step never opened this file".
    const at = headInsertionPoint(out);
    out = at === 0 ? `${tag}\n${out}` : `${out.slice(0, at)}\n  ${tag}${out.slice(at)}`;
  }
  return out;
}

/**
 * robots.txt, per mode (ARCHITECTURE.md, "Crawl posture").
 *
 * public: allow everything and point at the sitemap.
 * gated:  Disallow: /. The Access gate is the real protection and robots.txt is
 *         a request rather than a control, but an unlaunched client site must
 *         not be indexed even if something slips -- and a file left over from a
 *         previous mode saying `Allow: /` on a site under review is precisely
 *         the kind of stale artifact this step exists to eliminate. Both modes
 *         emit; neither inherits.
 */
export function robotsTxt(mode, origin) {
  const header =
    `# Generated by the Rocket Sites publisher on every deploy.\n` +
    `# Editing this file in the site repo has no effect -- it is overwritten.\n`;
  if (mode === "gated") {
    return (
      `${header}# mode: gated -- this site is in pre-launch client review and is behind\n` +
      `# Cloudflare Access. Nothing here is meant to be indexed yet.\n` +
      `User-agent: *\nDisallow: /\n`
    );
  }
  return `${header}User-agent: *\nAllow: /\n\nSitemap: ${origin}/sitemap.xml\n`;
}

const xmlEscape = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * sitemap.xml over the pages actually being uploaded.
 *
 * No <lastmod>. The only date this step could honestly write is "the moment of
 * this deploy", which would claim every page changed every time anyone
 * redeployed anything -- a signal crawlers learn to ignore, and worse than
 * omitting the field.
 */
export function sitemapXml(origin, urlPaths) {
  const entries = [...urlPaths]
    .sort()
    .map((p) => `  <url>\n    <loc>${xmlEscape(origin + p)}</loc>\n  </url>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries}\n</urlset>\n`;
}

export async function runStampSiteUrl({ env, logger, outputs, fetchImpl }) {
  const mode = readExplicit(env, "MODE");
  const dir = readExplicit(env, "PUBLISH_DIR");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const declared = readExplicit(env, "CUSTOM_DOMAIN").trim();

  if (!isValidMode(mode)) {
    logger.error(
      `Refusing to stamp the site's URL: mode '${mode}' is not one of ${MODES.join(", ")}, so the crawl ` +
        `posture for this deploy is undefined. Nothing was written and nothing was uploaded.`
    );
    return 1;
  }
  if (!fs.existsSync(dir)) {
    logger.error(`Publish directory '${dir}' does not exist -- there is nothing to stamp.`);
    return 1;
  }

  // Refuse before writing, and before touching Cloudflare (issue #141). This
  // step writes a whole rewritten document back over every page it walks, so a
  // symbolic link walked as a page is a write straight through it to a path
  // outside the publish directory.
  const { files: regular, refused } = walkArtifact(dir);
  if (reportRefusals(refused, (file, line, msg) => logger.errorAt(path.relative(dir, file) || file, line, msg)) > 0) {
    logger.error(
      `The publish directory contains ${refused.length} entr${refused.length === 1 ? "y" : "ies"} that ` +
        `${refused.length === 1 ? "is" : "are"} not a regular file. Nothing was stamped and NOTHING WAS UPLOADED.`
    );
    return 1;
  }

  const cf = createCloudflare({
    accountId: readExplicit(env, "CLOUDFLARE_ACCOUNT_ID"),
    token: readExplicit(env, "CLOUDFLARE_API_TOKEN"),
    fetchImpl,
  });
  const resolved = await resolveDomain(cf, projectName, logger);

  // Act on proof, never on assumption (invariant 1). With the project
  // unreadable and nothing declared, the only host available is the guess
  // `<project>.pages.dev` -- and on a global pages.dev name collision that host
  // belongs to a DIFFERENT Cloudflare account, so stamping it would point every
  // page's canonical at a stranger's website. That is worse than the placeholder
  // this step exists to remove. Fail instead: nothing has been uploaded.
  if (!resolved.domain && !declared) {
    logger.error(
      `Cannot determine the URL this site is served at: the Cloudflare Pages project '${projectName}' ` +
        `${resolved.readOk ? "reports no .subdomain" : "could not be read"}, so its real host is ` +
        `unknown, and no \`custom-domain:\` was declared. The publisher will not fall back to ` +
        `'${projectName}.pages.dev': that name is a guess, and on a global pages.dev name collision it ` +
        `belongs to a different Cloudflare account -- every page would tell search engines the ` +
        `canonical copy of this client's site lives on somebody else's domain. NOTHING WAS UPLOADED. ` +
        `Re-run; if it persists, check the Cloudflare token and account id, or declare ` +
        `\`custom-domain:\`.`
    );
    return 1;
  }

  const reconciled = reconcileCustomDomains({
    declared,
    discovered: resolved.customDomains,
    projectExists: resolved.projectExists,
    pagesDomain: resolved.domain,
  });
  for (const w of reconciled.warnings) logger.warning(w);
  if (!reconciled.ok) {
    logger.error(reconciled.error);
    return 1;
  }

  const origin = `https://${reconciled.canonicalHost}`;
  logger.info(
    `Canonical origin for this deploy: ${origin} (serving on ${reconciled.serving.join(", ")}). ` +
      `Every page's canonical, og:url and absolute og:image is rewritten to it.`
  );

  const pages = regular.filter((f) => /\.html?$/i.test(f));
  if (pages.length === 0) {
    logger.error(`No HTML pages in '${dir}' -- there is no site to stamp.`);
    return 1;
  }

  const urlPaths = [];
  for (const file of pages) {
    const rel = path.relative(dir, file);
    const indexable = !NOT_INDEXABLE.has(rel.split(path.sep).join("/"));
    const pageUrl = origin + pageUrlPath(rel);
    const before = fs.readFileSync(file, "utf8");
    const after = rewritePage(before, { origin, pageUrl, indexable });
    if (after !== before) fs.writeFileSync(file, after);
    if (indexable) urlPaths.push(pageUrlPath(rel));
  }
  logger.info(`Stamped the canonical URL into ${pages.length} page(s).`);

  // robots.txt and sitemap.xml are the publisher's files, not the site's. A
  // hand-written one in the repo is replaced, loudly, for the same reason the
  // source-repo meta is replaced: only the publisher knows the serving origin,
  // and a stale robots.txt from a previous mode is the failure being prevented.
  for (const name of ["robots.txt", "sitemap.xml"]) {
    if (fs.existsSync(path.join(dir, name))) {
      logger.warning(
        `Replacing the ${name} that shipped in the site repo. The publisher owns this file because it ` +
          `is the only party that knows the serving origin and the publication mode.`
      );
    }
  }
  fs.writeFileSync(path.join(dir, "robots.txt"), robotsTxt(mode, origin));

  const sitemapPath = path.join(dir, "sitemap.xml");
  if (mode === "gated") {
    // No sitemap for a site nobody is invited to crawl. Emitting one and then
    // asking robots not to read it is a contradiction shipped as bytes.
    //
    // EVERY sitemap, anywhere in the artifact (issue #139). This was a single
    // `rmSync(dir/sitemap.xml)`, so `blog/sitemap.xml`, `sitemap_index.xml` and
    // `sitemap.xml.gz` all survived a gated run -- and a crawler that already
    // holds one of those URLs does not ask robots.txt for permission to remember
    // what it found there.
    const removed = [];
    for (const file of regular) {
      if (!SITEMAP_FILE_RE.test(path.basename(file))) continue;
      fs.rmSync(file);
      removed.push(path.relative(dir, file).split(path.sep).join("/"));
    }
    logger.info(
      `mode: gated -- robots.txt disallows everything and no sitemap is published` +
        `${removed.length > 0 ? ` (removed ${removed.join(", ")} from the artifact)` : ""}.`
    );
  } else {
    fs.writeFileSync(sitemapPath, sitemapXml(origin, urlPaths));
    logger.info(`Published sitemap.xml with ${urlPaths.length} URL(s) and a robots.txt allowing crawlers.`);
  }

  outputs.set("canonical-origin", origin);
  outputs.set("canonical-host", reconciled.canonicalHost);
  outputs.set("serving-domains", reconciled.serving.join(","));
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  const outputs = createOutputs(process.env);
  process.exit(await runStampSiteUrl({ env: process.env, logger, outputs }));
}
