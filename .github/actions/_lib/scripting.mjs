// The scripting rule, on the bytes a client site is about to publish (#166).
//
// ── Why the publisher has this rule at all ───────────────────────────────
//
// core/src/lib/content-safety.ts refuses a model-authored `<script>` and every
// inline event handler, and it is the layer the repo owner actually hit. It runs
// in the extension, which means it only ever sees an edit made THROUGH THE
// PANEL. A hand edit, another tool, or a template updated in a repo that has
// since diverged reaches an agency's runner with nothing having looked at it --
// the same route #147 found for the legal rule, and the same answer: the
// artifact guard is the only check that reads what a client site actually
// publishes, so the rule belongs here too.
//
// ── Why this file is a COPY ──────────────────────────────────────────────
//
// core/src/lib/scripting.json is the one source. The publisher runs standalone
// from a tag, in an agency's Actions runner, with no build step and no core/ to
// import -- the constraint that gave #138 its own tokeniser in html.mjs and #147
// its own vendored legal data. So the data is vendored, and the copy is kept
// honest by two checks rather than by a comment asking people to remember:
//
//   tests/publisher/scripting-drift.test.mjs compares every field below against
//     core/src/lib/scripting.json. Editing one without the other turns CI red.
//   this file is a released publisher file, so its bytes are hashed into
//     .github/publisher-release.json, and editing it without cutting a release
//     turns the drift check red.
//
// ── WHAT IT REFUSES, AND WHAT IT DELIBERATELY DOES NOT ───────────────────
//
// A published Rocket Site RUNS JAVASCRIPT. That is the correction #166 is
// about: "no server behind it" and "no scripting in it" are different claims,
// and only the first one is true. The templates ship a `behaviours.js` and
// switch each behaviour on with a slot, so a same-origin `<script src>` is an
// ordinary part of a correct site and is not refused here.
//
// What is refused:
//
//   an inline event handler   `onclick=`, `onerror=`. It is a script written
//                             where nothing can tell a harmless one from an
//                             exfiltration, and it is the form that needs no
//                             <script> element and no src. Template-shipped
//                             behaviour has no use for one, because a template
//                             ships a real file that can addEventListener.
//   an executable URL         `javascript:`, `vbscript:`, `livescript:` in an
//                             attribute the browser navigates to or fetches.
//   a scriptable data: URI    `data:text/html`, `data:image/svg+xml` and the
//                             JavaScript media types, plus ANY data: URI on a
//                             navigating attribute.
//
// THE data: NARROWING IS DELIBERATE AND IS THE ONE PLACE THIS DIFFERS FROM THE
// EDIT GUARD. That guard has an ORIGINAL to diff against, so it only ever sees
// a data: URI the change ADDED and refuses all of them. This one has a single
// document and nothing to compare it to: a hand-authored static site inlining a
// small `data:image/png` is ordinary and correct, and failing a publish on it
// would break correct sites for no gain. The same asymmetry, for the same
// reason, as invariant 13's legal narrowing.
//
// A foreign `<script src>` is refused by rule 4 and not here, because that is a
// question about ORIGIN rather than about execution, and rule 4 already answers
// it for stylesheets in the same breath.

import { scanHtml } from "./html.mjs";

/** Where the data below comes from. Named so a reader can go and check. */
export const VENDORED_FROM = "core/src/lib/scripting.json";

/** `on*` in any casing: attribute names are lowercased by the scanner. */
export const EVENT_HANDLER_ATTR = "^on[a-z]+$";

/** Schemes that carry a payload rather than address a resource. */
export const EXECUTABLE_SCHEMES = Object.freeze([
  "javascript",
  "vbscript",
  "livescript",
  "data",
]);

/** Attributes whose value is a URL the browser navigates to or submits to. */
export const NAVIGATING_ATTRS = Object.freeze([
  "href",
  "xlink:href",
  "action",
  "formaction",
  "ping",
]);

/** Attributes whose value is a URL the browser FETCHES while rendering. */
export const FETCHING_ATTRS = Object.freeze([
  "src",
  "srcset",
  "data",
  "poster",
  "background",
]);

/** data: media types that can carry script. See the header. */
export const SCRIPTABLE_DATA_TYPES = Object.freeze([
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/javascript",
  "application/javascript",
  "application/ecmascript",
  "text/ecmascript",
]);

/** The slot namespace a template marks its shipped behaviours with. */
export const BEHAVIOUR_SLOT_PREFIX = "behaviour.";

/**
 * Elements where `href` FETCHES rather than navigates.
 *
 * `href` is in NAVIGATING_ATTRS because that is what it does on an `<a>`. On a
 * `<link>` it does the opposite: the browser pulls the resource in while
 * rendering and there is nowhere to follow it to. Without this carve-out an
 * inlined favicon -- `<link rel="icon" href="data:image/x-icon;base64,...">`,
 * which is ordinary and correct on a hand-authored static site -- fails the
 * publish under the "on an attribute the browser navigates to" branch, which is
 * precisely the case the header above says is left alone on purpose. Measured,
 * not reasoned about: the first draft of this file refused it.
 *
 * A scriptable media type on a `<link href>` is still refused, by the other
 * branch, because `data:image/svg+xml` and `data:text/html` carry script
 * wherever they are loaded.
 */
const HREF_FETCHES_ON = new Set(["link"]);

const NAMED_ENTITIES = {
  lt: "<", gt: ">", amp: "&", quot: '"', apos: "'",
  colon: ":", tab: "\t", newline: "\n", sol: "/", nbsp: " ",
};

/**
 * Decode enough of HTML's character references to see a URL scheme.
 *
 * `&#106;avascript&colon;alert(1)` is a working javascript: URL: the browser
 * decodes an attribute value before it parses the scheme, so a reader that
 * looks at the raw source sees a string starting with "&" and lets it through.
 * The trailing semicolon is optional in a numeric reference and browsers accept
 * it missing, so this does too. Same rule, same spelling, as core's copy.
 */
export function decodeEntities(value) {
  return String(value ?? "").replace(
    /&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);?/g,
    (whole, body) => {
      if (body[0] === "#") {
        const hex = body[1] === "x" || body[1] === "X";
        const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
        if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
        try {
          return String.fromCodePoint(code);
        } catch {
          return whole;
        }
      }
      return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
    },
  );
}

/** Characters a browser ignores inside a URL before it parses the scheme. */
const URL_NOISE = /[\u0000-\u0020\u007f]/g;

/** The URL with the noise a browser ignores taken out, entities decoded. */
const normaliseUrl = (value) => decodeEntities(value).replace(URL_NOISE, "");

/** The scheme a browser would see, or "" for a relative URL. */
export function urlScheme(value) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(normaliseUrl(value));
  return m ? m[1].toLowerCase() : "";
}

/** The media type of a `data:` URI, lowercased, or "" when it declares none. */
export function dataMediaType(value) {
  const rest = normaliseUrl(value).slice("data:".length);
  return rest.split(/[;,]/, 1)[0].trim().toLowerCase();
}

/**
 * Every refusable construct in one page, in document order.
 *
 * Runs off scanHtml, which is the publisher's ONE understanding of HTML syntax:
 * markup inside a comment is not markup here for the same reason it is not
 * markup to the browser, and a <script> body is raw text rather than a source of
 * invented elements. A second regex here would be a second opinion about what
 * the page says, and a page the guard and the browser read differently is the
 * whole shape of #125.
 */
export function scriptingProblems(html) {
  const handler = new RegExp(EVENT_HANDLER_ATTR);
  const urlAttrs = new Set([...NAVIGATING_ATTRS, ...FETCHING_ATTRS]);
  const navigating = new Set(NAVIGATING_ATTRS);
  const problems = [];

  for (const tag of scanHtml(html).tags) {
    for (const [name, value] of Object.entries(tag.attrs)) {
      if (handler.test(name)) {
        problems.push({
          index: tag.start,
          message:
            `carries the inline event handler ${name}="..." on <${tag.name}>. An inline handler is a ` +
            `script written where nothing can tell a harmless one from an exfiltration, and it is the ` +
            `form that needs no <script> element and no src. This is not a ban on JavaScript: a ` +
            `published Rocket Site is static files with no server behind it, and client-side script ` +
            `runs there fine -- the templates ship their behaviours in behaviours.js and switch each ` +
            `one on with a ${BEHAVIOUR_SLOT_PREFIX}* slot. Move the handler into a script file and ` +
            `attach it with addEventListener.`,
        });
        continue;
      }
      if (!urlAttrs.has(name)) continue;

      const scheme = urlScheme(value);
      if (!EXECUTABLE_SCHEMES.includes(scheme)) continue;

      if (scheme === "data") {
        const type = dataMediaType(value);
        const scriptable = SCRIPTABLE_DATA_TYPES.includes(type);
        const navigates =
          navigating.has(name) && !(name === "href" && HREF_FETCHES_ON.has(tag.name));
        if (!scriptable && !navigates) continue;
        problems.push({
          index: tag.start,
          message:
            `points ${name}= at a data: URI ${scriptable ? `of type ${type}` : "on an attribute the browser navigates to"} ` +
            `on <${tag.name}>. A data: URI carries its own document, so this one runs on the client's ` +
            `own origin the moment the browser loads it or a visitor follows it. A data: URI holding a ` +
            `plain raster image is left alone on purpose; this is not one.`,
        });
        continue;
      }

      problems.push({
        index: tag.start,
        message:
          `points ${name}= at a ${scheme}: URL on <${tag.name}>. A ${scheme}: URL carries its own ` +
          `payload rather than addressing a resource, so it runs on the client's own origin the moment ` +
          `a visitor follows it or the browser loads it. Entity-encoded and whitespace-split spellings ` +
          `are read the way a browser reads them, so there is nothing to be gained by writing it ` +
          `differently.`,
      });
    }
  }
  return problems.sort((a, b) => a.index - b.index);
}

// ═══════════════════════════════════════════════════════════════════════════
// The permitted embed (issue #292), vendored from the same scripting.json.
//
// ── The gap this closes, which is NOT the one #292 described ──────────────
//
// #292 said both enforcement points refuse an `<iframe>`. Only one did. The
// artifact guard's `findExternalAssets` matches `<link>` and `<script>` and
// nothing else, so until this rule an `<iframe>` pointing anywhere at all -- an
// ad network, a phishing form, a competitor's site -- published onto a client's
// live site with no complaint, provided a person put it in the repository by
// hand rather than through the panel. #278 is the issue that had this right.
//
// So this rule widens the EDIT path and tightens the PUBLISH path in one
// change, and the second half is the larger one.
//
// ── What is permitted, and what the guard still will not read ─────────────
//
// An `<iframe>` whose `src` leaves the site's own origin must name one of the
// three hosts in scripting.json, under that host's path prefix, over https:,
// with a `sandbox` whose tokens are all on the list and an `allow=` whose
// features all are. Everything else framing a foreign document -- `<object>`,
// `<embed>`, `<frame>`, `<portal>`, `<applet>` -- is refused with no allowlist,
// because a plugin document is a script host rather than a bounded rectangle.
//
// TWO DELIBERATE DIFFERENCES FROM THE EDIT GUARD, both the same asymmetry as
// the data: narrowing above and invariant 13's legal one. That guard has an
// ORIGINAL to diff against and only ever sees what a change ADDED; this one has
// a single document and nothing to compare it to.
//
//   a SAME-ORIGIN frame passes here.   `<iframe src="/enquiry.html">` and
//     `<object data="/brochure.pdf">` are ordinary on a hand-authored static
//     site and take nothing off the client's origin. The edit guard refuses
//     them because a model composing one is composing markup dictated by an
//     untrusted page; a site that already has one is not that.
//   `<base>` is NOT here.   The edit guard refuses every one, because adding a
//     `<base>` to a page is only ever a retarget. `<base href="/">` in a
//     hand-authored site is correct and common, and failing a publish on it
//     would be a blocked deploy with a diagnostic the author can disprove by
//     reading the tag -- the harm #219 weighed and called a defect.
//
// `srcdoc` IS refused here, on any element, and that closes a hole rather than
// opening one: it is a whole HTML document written as an attribute value, it
// runs on the client's own origin, no honest static site carries one, and no
// rule in this guard looked at it before.
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The embed hosts, with the path prefix each is permitted under.
 *
 * `www.google.com` serves the whole application, so a host-only entry would
 * permit framing anything Google hosts. The prefix is why this is a list of
 * entries and not a list of hostnames.
 */
export const EMBED_HOSTS = Object.freeze([
  Object.freeze({ host: "player.vimeo.com", path: "/video" }),
  Object.freeze({ host: "www.youtube-nocookie.com", path: "/embed" }),
  Object.freeze({ host: "www.google.com", path: "/maps/embed" }),
]);

/** Every token a permitted embed's required `sandbox` may carry. */
export const EMBED_SANDBOX = Object.freeze([
  "allow-scripts",
  "allow-same-origin",
  "allow-presentation",
]);

/** Every Permissions Policy feature a permitted embed's `allow=` may delegate. */
export const EMBED_ALLOW = Object.freeze([
  "autoplay",
  "fullscreen",
  "picture-in-picture",
  "encrypted-media",
]);

/**
 * Framing elements with no allowlist, and the attribute each frames with.
 *
 * `<frameset>` is not here: it has no source of its own and its children are
 * `<frame>`, which is. Refusing a container that fetches nothing would be a
 * rule about page structure wearing a security rule's clothes.
 */
export const FOREIGN_FRAMING_TAGS = Object.freeze({
  frame: "src",
  portal: "src",
  object: "data",
  embed: "src",
  applet: "code",
});

/** The three entries as an operator should ask for them. */
export const EMBED_HOSTS_SPELLED = EMBED_HOSTS.map((e) => `${e.host}${e.path}`).join(", ");

/** Absolute or protocol-relative, read the way a browser reads it. */
function leavesThisOrigin(value) {
  return /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(normaliseUrl(value));
}

/** The URL a browser would resolve, or null when there is not one. */
function embedUrl(value) {
  const decoded = normaliseUrl(value);
  if (decoded === "") return null;
  try {
    return new URL(decoded);
  } catch {
    return null;
  }
}

const tokensOf = (value) =>
  String(value ?? "").trim().toLowerCase().split(/\s+/).filter(Boolean);

/**
 * The features an `allow=` delegates. Permissions Policy syntax is
 * `feature allowlist; feature allowlist`, so the feature is the first token of
 * each `;`-separated part.
 */
const allowFeatures = (value) =>
  String(value ?? "")
    .split(";")
    .map((part) => part.trim().split(/\s+/)[0] ?? "")
    .filter(Boolean)
    .map((f) => f.toLowerCase());

/**
 * Why this `<iframe>` is refused, or null when it is a permitted embed.
 *
 * SECOND IMPLEMENTATION OF core/src/lib/content-safety.ts's `embedRefusal`, for
 * the reason at the top of this file. The DATA is one copy; the two readings of
 * it are held together by `core/tests/embed-cases.json`, a corpus of markup with
 * a verdict per surface that both suites drive. A field-by-field comparison of
 * the data would have said nothing about two readings that disagree, and
 * disagreeing readings of one list is #126 wearing a hat.
 *
 * Every branch NAMES what it refused, because the operator's next move is to
 * ask for it: a host to add to the list, a `sandbox` to write, an `allow=` token
 * to delete from a snippet pasted out of a vendor's share dialog.
 */
export function embedRefusal(attrs) {
  const named = `The embeds a Rocket Site permits are ${EMBED_HOSTS_SPELLED}, and nothing else.`;

  if (typeof attrs.srcdoc === "string") {
    return `it carries srcdoc, which is a whole HTML document written as an attribute value and running on the client's own origin. A permitted embed addresses a player by https: URL; it does not carry a document of its own.`;
  }

  const raw = attrs.src ?? "";
  if (String(raw).trim() === "") {
    return `it has no src. A frame with nothing in it is refused rather than ignored, because what fills it later is decided somewhere this guard cannot read. ${named}`;
  }

  const url = embedUrl(raw);
  if (url === null) {
    const scheme = urlScheme(raw);
    return scheme === ""
      ? `its src is a relative or protocol-relative address ("${String(raw).trim()}"). A permitted embed names its origin in full, as an absolute https: URL, so what is being framed is a fact about the markup rather than about wherever the page happens to be served from. ${named}`
      : `its src is not a URL a browser can resolve ("${String(raw).trim()}"). ${named}`;
  }

  if (url.protocol !== "https:") {
    return `its src is a ${url.protocol.replace(/:$/, "")}: URL. Only https: is permitted: a frame loaded over anything else is a document any network between the visitor and the player can rewrite, inside a page the client's domain is vouching for. ${named}`;
  }

  if (url.username !== "" || url.password !== "") {
    return `its src carries credentials before the host ("${url.username}@..."). That is the oldest way to write a URL that reads as one host and resolves to another, and the host it actually resolves to is ${url.hostname}. ${named}`;
  }

  if (url.port !== "") {
    return `its src names an explicit port (${url.hostname}:${url.port}). A permitted embed is a player on its own https: port; a port here is a different service on a name this list vouches for. ${named}`;
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const entry = EMBED_HOSTS.find(
    (e) => e.host === host && (url.pathname === e.path || url.pathname.startsWith(`${e.path}/`)),
  );
  if (!entry) {
    const hostMatch = EMBED_HOSTS.find((e) => e.host === host);
    return hostMatch
      ? `its src is on ${host}, which is permitted only under ${hostMatch.path}, and this one is ${url.pathname}. That host serves more than the embed, so the path is part of what was allowed. ${named}`
      : `its src frames ${host}, which is not an embed host a Rocket Site permits. ${named} Ask for ${host} to be added if it belongs there: the list is code, in core/src/lib/scripting.json, and adding to it is a decision somebody makes once rather than a setting a page can carry.`;
  }

  const sandbox = attrs.sandbox;
  if (typeof sandbox !== "string") {
    return `it has no sandbox attribute. A permitted embed carries one, because without it the framed document can navigate the visitor's whole window off the client's site, and a visitor cannot tell that apart from the client doing it. Write sandbox="${EMBED_SANDBOX.join(" ")}".`;
  }
  const badSandbox = tokensOf(sandbox).filter((t) => !EMBED_SANDBOX.includes(t));
  if (badSandbox.length > 0) {
    return `its sandbox grants ${badSandbox.join(", ")}, which a player does not need to play a video. The permitted tokens are ${EMBED_SANDBOX.join(", ")}; everything else is a way for somebody else's document to act as though it were the client's.`;
  }

  const badAllow = allowFeatures(attrs.allow ?? "").filter((f) => !EMBED_ALLOW.includes(f));
  if (badAllow.length > 0) {
    return `its allow= delegates ${badAllow.join(", ")} to the document in the frame. The permitted features are ${EMBED_ALLOW.join(", ")}: each of those changes how the frame plays media, and each of the ones named above hands it a capability that reaches outside its own rectangle. Vendors' copy-paste snippets ask for more than they need; deleting the named token leaves a working player.`;
  }

  return null;
}

/**
 * Every foreign document this page frames that it may not, in document order.
 *
 * Runs off the same scanHtml as `scriptingProblems`, for the same reason: one
 * understanding of what the page says, so markup in a comment is not markup and
 * a code sample is not a frame.
 */
export function embedProblems(html) {
  const problems = [];

  for (const tag of scanHtml(html).tags) {
    // A document written as an attribute value, on any element. No honest
    // static site carries one, and nothing else in this guard looks at it.
    if (typeof tag.attrs.srcdoc === "string") {
      problems.push({
        index: tag.start,
        message:
          `carries srcdoc on <${tag.name}>. That is a whole HTML document written as an attribute value, ` +
          `and everything in it runs on the client's own origin, with the client's domain in the address ` +
          `bar. Put the markup in a page of its own.`,
      });
      continue;
    }

    if (tag.name === "iframe") {
      // Same-origin frames pass: see the header. A frame that leaves the origin
      // is the one this rule is about. A `srcdoc` frame never reaches here --
      // the branch above took it, on every element rather than only this one.
      if (!leavesThisOrigin(tag.attrs.src ?? "")) continue;
      const why = embedRefusal(tag.attrs);
      if (why === null) continue;
      problems.push({
        index: tag.start,
        message:
          `frames a document from another origin and ${why} A Rocket Site CAN carry a video player or a ` +
          `map: an <iframe> is permitted from three named origins, over https:, with a sandbox. This one ` +
          `is not one of those, so it publishes nothing.`,
      });
      continue;
    }

    const framingAttr = FOREIGN_FRAMING_TAGS[tag.name];
    if (framingAttr === undefined) continue;
    const value = tag.attrs[framingAttr] ?? "";
    if (!leavesThisOrigin(value)) continue;
    const url = embedUrl(value);
    problems.push({
      index: tag.start,
      message:
        `embeds ${url ? url.hostname : String(value).trim()} with <${tag.name} ${framingAttr}=>. There is ` +
        `no allowlist for this element, as there is for <iframe>: a plugin document is a script host ` +
        `rather than a bounded rectangle, so no origin makes one safe. If this is a video or a map, use ` +
        `an <iframe> from ${EMBED_HOSTS_SPELLED}.`,
    });
  }

  return problems.sort((a, b) => a.index - b.index);
}
