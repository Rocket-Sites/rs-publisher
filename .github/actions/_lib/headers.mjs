// The response headers every Rocket Site serves, and the bytes that set them.
//
// ── The gap this closes (issue #260) ─────────────────────────────────────
//
// No Rocket Site has ever served a security header. Grepping the publisher and
// the templates for `X-Frame-Options`, `X-Content-Type-Options` or
// `Content-Security-Policy` returned nothing, so every site this product has
// published serves with Cloudflare's defaults and nothing else: frameable,
// sniffable, and leaking a full referrer to every outbound link. That is not a
// bug anybody was going to notice. Nothing breaks, no page looks wrong, and the
// consequence arrives later as a security finding rather than as a red run.
//
// Cloudflare Pages has exactly one mechanism for a response header on a static
// site, and it is a `_headers` file at the root of the uploaded directory. So
// the choice was never "headers or no file". It was WHOSE file.
//
// ── Why the publisher writes it, rather than a site declaring it ─────────
//
// Three shapes were available: a `_headers` shipped by a template, a block in
// `rocket-site.json` compiled into one, or a constant here that the publisher
// writes into every artifact. The third is the one that fits, for two reasons
// that point the same way.
//
// A SITE REPOSITORY'S OWN `_headers` STAYS REFUSED, and #121's reasoning is
// untouched by any of this. A file from the repo can strip a header as easily
// as set one, and it makes the response something you cannot learn by reading
// the artifact -- the first of the two reasons CLAUDE.md hard rule 1 gives for
// banning a Pages Function. The rsync deny-list and the artifact guard both
// still refuse one, and the guard now refuses anything at that path whose bytes
// are not the ones below.
//
// AND A DECLARATION IS A THING AN UNATTENDED GENERATOR DROPS. Since hard rule 7
// a client asks for a website and gets one with nobody in the loop, so anything
// a site has to remember to declare is something no first-generation site will
// ever have. A per-site slot for security headers would be empty on every site
// this product creates, which is exactly the state #260 was filed about, only
// now with a schema field pointing at it. A constant applied to every artifact
// is the only version of this that is true of site N+1 as well as site N.
//
// The set is the one measured on Rocket Lab's own CRM site
// (`~/work/crm/www/_headers`), not invented here. Four headers, each safe on a
// static marketing site with no server behind it and no framing use:
//
//   X-Frame-Options          clickjacking. DENY rather than SAMEORIGIN: a
//                            Rocket Site has no frame of its own to sit in.
//   X-Content-Type-Options   MIME sniffing, which turns an uploaded asset into
//                            whatever a browser guesses it is.
//   Referrer-Policy          stops a client's full URLs reaching every site
//                            their pages link out to.
//   Permissions-Policy       the three device APIs a marketing site never asks
//                            for, denied so that nothing on the page can.
//
// NOT Content-Security-Policy, deliberately. A CSP that a template has not been
// authored against fails a page rather than a publish: the styles or the
// `behaviours.js` a slot switched on stop working, in a visitor's browser,
// where no guard here is watching. It is worth having and it is a templates
// change with its own testing, not a constant somebody adds in passing.
//
// ── `_redirects` is NOT here, and that is a decision (#260) ──────────────
//
// The same file family carries redirects, and the publisher does not write one.
// A redirect map is per-site data -- there is no constant that is right for two
// sites -- so the only shape that could work is a validated block in
// `rocket-site.json` compiled here. That is worth building when something can
// author it, and today nothing can: unattended creation means the block would
// be absent on every site, which buys nothing that this file's argument does
// not already say. It also has to close the gate-proof forgery BY
// CONSTRUCTION, because one line of `_redirects` pointing at
// `/cdn-cgi/access/login` makes an ungated project answer the shape
// post-deploy-verify reads as a Cloudflare Access gate. #260 records the
// design; nothing about it is started here.

/**
 * The headers, as decisions rather than as text. One place, so the mutation
 * manifest has something to corrupt and the tests have something to read.
 */
export const SECURITY_HEADERS = Object.freeze([
  Object.freeze(["X-Frame-Options", "DENY"]),
  Object.freeze(["X-Content-Type-Options", "nosniff"]),
  Object.freeze(["Referrer-Policy", "strict-origin-when-cross-origin"]),
  Object.freeze(["Permissions-Policy", "geolocation=(), microphone=(), camera=()"]),
]);

/** The entry name Cloudflare Pages reads these from, at the deploy root only. */
export const HEADERS_ENTRY = "_headers";

/**
 * The exact bytes the publisher writes, and the exact bytes the artifact guard
 * requires to be there. Rendered from SECURITY_HEADERS so the two can never
 * disagree: a second copy of a header value is a second place to fix it.
 */
export const PAGES_HEADERS =
  `# Written by the Rocket Sites publisher. Never read from a site repository:\n` +
  `# a _headers committed there is excluded from the upload and fails the\n` +
  `# artifact guard, because what a visitor is served has to be something you\n` +
  `# can learn by reading these bytes. See .github/actions/_lib/headers.mjs.\n` +
  `/*\n` +
  SECURITY_HEADERS.map(([name, value]) => `  ${name}: ${value}\n`).join("");

/**
 * Parse Cloudflare's `_headers` format into rules, so a test can ask what a
 * visitor is SERVED rather than whether a file contains a string.
 *
 * The distinction is the point. `assert.match(text, /X-Frame-Options/)` passes
 * on a file that names the header inside a comment, on one that indents it
 * under no path at all, and on one whose value is `ALLOWALL`. Each of those
 * ships a site with no clickjacking protection and a green test beside it.
 *
 * Format: a line in column 0 is a path pattern, and every indented `Name: value`
 * beneath it belongs to that pattern. `#` starts a comment. A header line
 * before any path is not addressed to anything and is dropped.
 */
export function parsePagesHeaders(text) {
  const rules = [];
  let current = null;
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/#.*$/, "");
    if (line.trim() === "") continue;
    if (!/^\s/.test(line)) {
      current = { path: line.trim(), headers: new Map() };
      rules.push(current);
      continue;
    }
    const at = line.indexOf(":");
    if (at === -1 || current === null) continue;
    current.headers.set(line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim());
  }
  return rules;
}

/**
 * Every header a visitor asking for `urlPath` is served, lower-cased names.
 *
 * Cloudflare applies every matching rule, later ones winning, and `:splat`-free
 * `*` globs are all this file uses -- so the match is the same trailing-wildcard
 * comparison Pages does, and nothing here pretends to be a full implementation
 * of a format the publisher only ever writes one shape of.
 */
export function headersFor(text, urlPath) {
  const out = new Map();
  for (const rule of parsePagesHeaders(text)) {
    const matches = rule.path.endsWith("*")
      ? urlPath.startsWith(rule.path.slice(0, -1))
      : urlPath === rule.path;
    if (matches) for (const [name, value] of rule.headers) out.set(name, value);
  }
  return out;
}
