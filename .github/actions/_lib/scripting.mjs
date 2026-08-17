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
