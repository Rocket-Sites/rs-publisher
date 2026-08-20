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
// ── One CSP directive, and only one: `frame-src` (#294) ─────────────────
//
// This block used to read, in full: *"NOT Content-Security-Policy,
// deliberately. A CSP that a template has not been authored against fails a
// page rather than a publish: the styles or the `behaviours.js` a slot switched
// on stop working, in a visitor's browser, where no guard here is watching. It
// is worth having and it is a templates change with its own testing, not a
// constant somebody adds in passing."*
//
// THAT REASON HOLDS, AND IT IS A REASON ABOUT `style-src` AND `script-src`. It
// names two failures and both are the same failure: a directive that governs a
// resource a template loads. `frame-src` governs neither. And a policy is not
// default-deny as a whole -- a directive that is ABSENT from the header is not
// enforced at all, and `default-src` is a fallback only when it is present. So
// a header carrying `frame-src` and nothing else restricts nested browsing
// contexts and leaves every stylesheet, script, font and image exactly as
// unrestricted as they are today. The declined reason does not engage with it,
// and a rule kept alive by a reason that does not apply is a rule the next
// person deletes.
//
// WHAT IT BUYS, which is the thing invariant 17 could not buy on its own. The
// embed allowlist is enforced by `_lib/scripting.mjs` at BUILD time, over the
// artifact. That is a check on the bytes we published. `frame-src` is the
// visitor's browser refusing to load the frame on every request, so markup that
// reaches a client's site by a route no guard inspected -- the exact shape of
// the hole #278 found, where a hand-edited repo published a foreign iframe with
// a green run for the whole life of the product -- gets a rectangle that does
// not load rather than somebody else's document on the client's domain.
//
// ONE COPY OF THE LIST. The sources below are DERIVED from `EMBED_HOSTS`, which
// is vendored from `core/src/lib/scripting.json`, which is the same data the
// edit guard and the artifact guard read. A hand-typed origin here would be the
// third copy of a list that has already been the subject of #126, where two
// copies of the legal vocabulary disagreed about `[DATE]`.
//
// ── What this header does NOT do, said plainly ──────────────────────────
//
// It enforces the ORIGIN half of invariant 17 and no other half. There is no
// CSP directive that can require a `sandbox` attribute on a frame (the
// `sandbox` DIRECTIVE sandboxes the response carrying it, which is a different
// thing and would break every site). So a frame on a permitted origin with no
// sandbox, or with `allow="camera"`, is refused at build time and permitted at
// run time. The guard is still the only place the whole rule exists.
//
// It is also, in three narrow spellings, MORE permissive than the guard, and
// each of those is harmless in the same way: the guard has already failed the
// publish, so the markup is not on the site for the browser to have an opinion
// about. A protocol-relative `//player.vimeo.com/video/1` resolves to https on
// an https page and matches; a `srcdoc` frame inherits the parent's policy
// rather than being fetched; and a frame refused for its sandbox is refused for
// something `frame-src` cannot see.
//
// And it is, in exactly ONE spelling, STRICTER than the guard, which is the
// only place this header can break a page that passed the artifact guard:
// `<iframe src="HTTPS://Player.Vimeo.COM./video/1">`. CSP matches a host by
// ASCII case-insensitive equality and the trailing dot is not equal, while the
// guard strips it because a browser resolves it. That case is in
// `core/tests/embed-cases.json`, it is named in the test below rather than
// papered over, and no vendor's snippet produces it. It costs one frame that
// does not load on markup nobody writes; the alternative was `frame-src https:`
// or nothing at all.
//
// ── Not report-only, and that is an argument rather than a default ──────
//
// `Content-Security-Policy-Report-Only` is the cautious first stage and it is
// the wrong one here, for two reasons that are specific to this product rather
// than to CSP.
//
// A report-only policy is a MECHANISM FOR LEARNING, and there is nothing here
// to learn with. It reports to a `report-uri`/`report-to` endpoint, and Rocket
// Lab has no endpoint a client's site may talk to: hard rule 1 keeps every
// Rocket Lab service out of the serving path of a client site, and standing one
// up to receive violation reports would put one there and collect visitor
// telemetry off client domains while doing it. Without a collector the header
// does exactly one observable thing -- a line in a console nobody has open --
// while announcing in every response that a policy is in force. That is a
// header that reads as protection and is not.
//
// And the population report-only exists to discover is already KNOWN. You send
// report-only when you cannot enumerate what a policy would break. Here the
// artifact guard has just read every framing element in every page of the
// artifact, and refused the publish over any it does not permit. The set of
// frames a site serves is derivable from the same bytes the header ships beside.
// Report-only would be asking visitors' browsers to tell us something the build
// already proved.
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

import { EMBED_HOSTS } from "./scripting.mjs";

/**
 * The `frame-src` source list, derived from the ONE copy of the embed
 * allowlist (#294). Never type an origin in here.
 *
 * TWO EXPRESSIONS PER ENTRY, AND BOTH ARE LOAD-BEARING. CSP's path matching
 * treats a source path ending in `/` as a prefix over path SEGMENTS and any
 * other path as an exact match, and the two do not subsume each other:
 *
 *   `https://www.google.com/maps/embed`   matches `/maps/embed` and nothing
 *                                         under it. This is the real Google
 *                                         Maps embed, whose URL is
 *                                         `/maps/embed?pb=...` with no
 *                                         trailing segment at all.
 *   `https://www.google.com/maps/embed/`  matches `/maps/embed/anything` and
 *                                         not `/maps/embed` itself. This is
 *                                         the Vimeo and YouTube shape,
 *                                         `/video/{id}` and `/embed/{id}`.
 *
 * Emitting only the first would break every video embed and only the second
 * would break every map, so the derivation emits both for every entry rather
 * than deciding per host which shape that host happens to use today. Together
 * they are exactly what `embedRefusal` permits: the segment, or a child of it.
 * They are NOT host-only, for the reason scripting.json gives about
 * `www.google.com` serving the whole application.
 *
 * `'self'` is first because the artifact guard deliberately PERMITS a
 * same-origin frame -- `<iframe src="/enquiry.html">` on a hand-authored static
 * site takes nothing off the client's origin -- and a header that refused what
 * the guard permits is this change breaking a live site invisibly, which is the
 * one failure mode it has. It also covers the same-origin frame Cloudflare's
 * own managed challenge injects at `/cdn-cgi/challenge-platform/`.
 */
export const FRAME_SRC_SOURCES = Object.freeze([
  "'self'",
  ...EMBED_HOSTS.flatMap((e) => [`https://${e.host}${e.path}`, `https://${e.host}${e.path}/`]),
]);

/**
 * The whole policy, and it is one directive on purpose. See the header: a
 * directive absent from a CSP is not enforced, so this restricts frames and
 * nothing else. Adding `script-src` or `style-src` here is the change the
 * declined reason above was actually about, and it needs the templates.
 */
export const CONTENT_SECURITY_POLICY = `frame-src ${FRAME_SRC_SOURCES.join(" ")}`;

/**
 * The headers, as decisions rather than as text. One place, so the mutation
 * manifest has something to corrupt and the tests have something to read.
 */
export const SECURITY_HEADERS = Object.freeze([
  Object.freeze(["X-Frame-Options", "DENY"]),
  Object.freeze(["X-Content-Type-Options", "nosniff"]),
  Object.freeze(["Referrer-Policy", "strict-origin-when-cross-origin"]),
  Object.freeze(["Permissions-Policy", "geolocation=(), microphone=(), camera=()"]),
  Object.freeze(["Content-Security-Policy", CONTENT_SECURITY_POLICY]),
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
