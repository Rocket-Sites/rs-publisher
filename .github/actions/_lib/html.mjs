// One understanding of HTML syntax for the whole publisher.
//
// ── Why this exists (issues #138 and #125) ───────────────────────────────
//
// Four things read `<meta name="source-repo">`, and the fourth is a browser.
// The other three were regexes, and each of them was wrong in a different way:
//
//   inject-source-meta anchored the insertion to the first TEXTUAL `<head`, so a
//     `<head>` inside a leading HTML comment took the tag. templates/beacon/
//     privacy.html and terms.html already ship a leading legal-review comment,
//     so nobody has to be hostile: write `<head>` into that comment and the page
//     ships with NO recognition tag in the DOM, both guards report pass, the
//     public post-deploy proof reports pass, and the extension declares the page
//     "not a Rocket Site" with nothing in the run to diagnose it.
//   declaredRepo took the FIRST QUOTED match, so a page could declare one repo
//     to the guard (from inside a comment) and another to the browser.
//   bodyDeclaresRepo -- the invariant 7 proof -- accepted ANY matching tag,
//     including one in a comment.
//
// And all three required quoted attributes, while the browser does not, so
// `<meta name=source-repo content=attacker/pwn>` was invisible to every check
// and authoritative in the one place that decides where an edit is committed
// (#125). There was no pattern to evade. The parsers simply disagreed about what
// an attribute is.
//
// So: one scanner, and the rule it implements is "what a browser would see".
// core/src/lib/html-slots.ts solves the same problem on the other side of the
// product and this is deliberately NOT it: the publisher runs standalone in an
// agency's Actions runner from a tag, with no build step and no core/ to import.
// Same approach, separate implementation, and core/tests/
// source-repo-agreement.test.mjs plus tests/publisher/artifact-guard.test.mjs
// hold the two to the same answers.
//
// It is a scanner, not a conformant parser. It understands tags, attributes in
// every quoting form, comments, CDATA, and raw-text elements. That is everything
// a Rocket Sites template uses, and anything it cannot make sense of is stepped
// over rather than guessed at.

/** Elements whose content is TEXT, so `<` inside them is not markup. */
const RAW_TEXT_TAGS = new Set(["script", "style", "textarea", "title", "noscript"]);

const TAG_RE =
  /<([a-zA-Z][a-zA-Z0-9:-]*)((?:\s+[^\s/>"'=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]*))?)*)\s*\/?>/g;

const ATTR_RE = /([^\s/>"'=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]*)))?/g;

/**
 * Attributes as a browser reads them: names lowercased, values taken from any of
 * the three quoting forms, whitespace around `=` ignored.
 */
function parseAttrs(raw) {
  const attrs = {};
  for (const m of String(raw ?? "").matchAll(ATTR_RE)) {
    const name = m[1]?.toLowerCase();
    if (!name) continue;
    if (!(name in attrs)) attrs[name] = m[2] ?? m[3] ?? m[4] ?? "";
  }
  return attrs;
}

/**
 * Where an attribute NAME may start, as a zero-width assertion (issue #219).
 *
 * `\b` is a word break, and a word break is not an attribute boundary. `-`, `:`,
 * `.` and `@` are all non-word characters, so `\bhref` asserts happily between
 * the `-` and the `h` of `data-href`, between the `:` and the `h` of
 * `xlink:href`, and inside `x-on:content` and `@poster`. Every regex in the
 * publisher that anchored an attribute name with `\b` was therefore matching a
 * DIFFERENT attribute whose name merely ends with the one it wanted -- and
 * because `String.replace` with a non-global regex takes the LEFTMOST match, a
 * decoy written before the real attribute is the one that gets rewritten while
 * the real one ships untouched.
 *
 * So the name is not anchored to a word break, it is anchored to "not preceded
 * by anything that would make this the tail of a longer name". Zero-width rather
 * than a consumed leading `[\s"']`, so it composes with `g` and shifts no
 * capture group, which is what let this replace `\b` everywhere in one shape.
 *
 * `core/src/lib/html-slots.ts` carries the same idiom for the extension side
 * (#221). Same approach, separate implementation, for the reason at the top of
 * this file: the publisher runs standalone in an agency's Actions runner with no
 * build step and no `core/` to import.
 */
export function attrNamePattern(name) {
  return `(?<![-.:@\\w])(?:${name})`;
}

/**
 * Every match of `re` in ONE opening tag's text that is really at an attribute
 * NAME position, in source order.
 *
 * What the lookbehind above cannot do. A tag's text is not a list of names: it
 * is names, `=`, and quoted values that may contain anything, including
 * something spelled exactly like an attribute. `data-note=" href='x'"` offers a
 * `href=` preceded by a space, so no assertion over the preceding character can
 * tell it apart from the real thing -- and it is the leftmost match, which is
 * the half of #219 that does the damage.
 *
 * Quote state, not quote counting. HTML attribute values have no escape
 * sequence, so a `'` inside a `"..."` value is an ordinary character and the
 * only correct reading is a left-to-right walk.
 *
 * `re` must carry `g`; its `lastIndex` is reset here so a module-level regex is
 * safe to reuse.
 */
export function* attrMatches(tagText, re) {
  const text = String(tagText ?? "");
  const values = [];
  let quote = "";
  let opened = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === quote) {
        values.push({ start: opened, end: i });
        quote = "";
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      opened = i;
    }
  }

  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0] === "") re.lastIndex += 1;
    if (values.some((span) => m.index > span.start && m.index < span.end)) continue;
    yield m;
  }
}

/**
 * Where a comment opening at `start` ends.
 *
 * A comment ends at the FIRST `-->`, whatever that `-->` looks like it sits
 * inside: there is no nesting and there are no attributes in a comment. `<!-->`
 * and `<!--->` are the spec's abrupt-closing forms and end right there --
 * searching past them for a later `-->` would swallow live markup.
 */
function commentEnd(html, start) {
  const i = start + 4;
  if (html[i] === ">") return i + 1;
  if (html[i] === "-" && html[i + 1] === ">") return i + 2;
  const close = html.indexOf("-->", i);
  return close === -1 ? html.length : close + 3;
}

/**
 * Where a `<!...` construct that is not a comment ends: a doctype, or the
 * "bogus comment" a stray declaration becomes.
 *
 * `<![CDATA[` is given the XML reading (`]]>`) rather than the HTML one (the
 * first `>`), because the CDATA sections that actually occur in a Rocket Site
 * are inside inline SVG, where that reading is the browser's. The two readings
 * disagree only about markup AFTER the construct, and both disagree in the
 * direction of counting a tag the other does not -- which fails a publish
 * loudly rather than shipping something unexamined.
 */
function declarationEnd(html, start) {
  if (html.startsWith("<![CDATA[", start)) {
    const close = html.indexOf("]]>", start + 9);
    return close === -1 ? html.length : close + 3;
  }
  const close = html.indexOf(">", start);
  return close === -1 ? html.length : close + 1;
}

/**
 * The one scan.
 *
 * Returns `{ tags, inert }`. `tags` are the elements a browser would build, in
 * document order. `inert` are the spans that are NOT markup -- comments,
 * declarations, and the content of raw-text elements -- so a regex-based reader
 * elsewhere can blank them and keep every offset.
 *
 * The order of the two lookups is what makes it right in both directions:
 * whichever comes FIRST, the next `<!` construct or the next tag, wins. So a
 * `<!--` inside a live element's attribute value opens nothing (the tag match
 * starts earlier and the cursor jumps past it), and a `<!--` inside a <script>
 * opens nothing (raw-text content is consumed whole when its opening tag is
 * read). Neither is achievable by blanking comments with a regex first.
 */
export function scanHtml(html) {
  const text = String(html ?? "");
  const tags = [];
  const inert = [];
  let cursor = 0;

  while (cursor < text.length) {
    TAG_RE.lastIndex = cursor;
    const m = TAG_RE.exec(text);
    const declAt = text.indexOf("<!", cursor);

    if (declAt !== -1 && (!m || declAt < m.index)) {
      const end = text.startsWith("<!--", declAt) ? commentEnd(text, declAt) : declarationEnd(text, declAt);
      inert.push({ start: declAt, end });
      cursor = end;
      continue;
    }
    if (!m) break;

    const name = m[1].toLowerCase();
    const tagEnd = m.index + m[0].length;
    tags.push({ name, attrs: parseAttrs(m[2] ?? ""), start: m.index, end: tagEnd });
    cursor = tagEnd;

    if (RAW_TEXT_TAGS.has(name) && !/\/>$/.test(m[0])) {
      // Everything to the matching close tag is text. Scanning it would invent
      // elements out of a string literal in a script, or out of the code sample
      // a page is deliberately displaying.
      const close = new RegExp(`</${name}\\s*>`, "i").exec(text.slice(tagEnd));
      const contentEnd = close ? tagEnd + close.index : text.length;
      if (contentEnd > tagEnd) inert.push({ start: tagEnd, end: contentEnd });
      cursor = close ? contentEnd + close[0].length : text.length;
    }
  }
  return { tags, inert };
}

/**
 * A copy of `html` with every inert span replaced by spaces.
 *
 * Length, offsets and line breaks are all preserved, so a match index into the
 * result addresses the same span of the original and a caller can splice back
 * into the real source. For the readers that are regexes because the thing they
 * look for is not an element -- a placeholder hostname, a CDN literal.
 */
export function blankInert(html) {
  const text = String(html ?? "");
  const { inert } = scanHtml(text);
  if (inert.length === 0) return text;
  // split("") and not [...text]: spreading iterates CODE POINTS, so one emoji in
  // a page's copy would shift every index after it.
  const chars = text.split("");
  for (const { start, end } of inert) {
    for (let i = start; i < end; i += 1) if (chars[i] !== "\n") chars[i] = " ";
  }
  return chars.join("");
}

/**
 * The HTML comments in `html`, as text, in document order.
 *
 * A comment is an inert span that opens `<!--`; a doctype and a bogus
 * declaration are inert too and are not comments. Taken from the one scan rather
 * than from `/<!--[\s\S]*?-->/g`, because that regex finds a "comment" inside a
 * <script> string literal and inside an attribute value, and misses the abrupt
 * closing forms -- which is the whole reason this module exists.
 */
export function comments(html) {
  const text = String(html ?? "");
  return scanHtml(text)
    .inert.filter((span) => text.startsWith("<!--", span.start))
    .map((span) => text.slice(span.start, span.end));
}

/**
 * A copy of `html` with every COMMENT blanked, and nothing else.
 *
 * Narrower than blankInert on purpose. Its callers ask "what does a reader
 * actually see on this page", and the content of a <title> is read by a person
 * while the content of a comment is not -- so blanking raw-text elements here
 * would make a placeholder in a page title look filled. Offsets, length and line
 * breaks are preserved, as in blankInert.
 */
export function blankComments(html) {
  const text = String(html ?? "");
  const spans = scanHtml(text).inert.filter((span) => text.startsWith("<!--", span.start));
  if (spans.length === 0) return text;
  const chars = text.split("");
  for (const { start, end } of spans) {
    for (let i = start; i < end; i += 1) if (chars[i] !== "\n") chars[i] = " ";
  }
  return chars.join("");
}

/**
 * Every match of `re` that is LIVE MARKUP, with the text taken from the real
 * source. For the readers whose target is a tag but whose pattern is a regex.
 *
 * The regex runs over the blanked copy, so a match cannot begin inside a comment
 * or inside a script -- and because blanking preserves every offset, `index`
 * still addresses the original.
 */
export function liveMatches(html, re) {
  const text = String(html ?? "");
  const blanked = blankInert(text);
  const pattern = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  return [...blanked.matchAll(pattern)].map((m) => ({ index: m.index, text: text.slice(m.index, m.index + m[0].length) }));
}

/** Rewrite every live match of `re` through `fn`, leaving inert copies alone. */
export function replaceLive(html, re, fn) {
  const text = String(html ?? "");
  let out = text;
  for (const m of liveMatches(text, re).reverse()) {
    out = out.slice(0, m.index) + fn(m.text) + out.slice(m.index + m.text.length);
  }
  return out;
}

/**
 * One attribute of one tag, read as a browser reads it: any quoting form, and
 * the FIRST occurrence wins when a tag carries the same attribute twice -- which
 * is the parser's rule, and the reason a duplicate attribute is a defect rather
 * than a stylistic matter (issue #139). Returns null when the tag has no such
 * attribute.
 */
export function tagAttr(tagText, name) {
  const tag = scanHtml(tagText).tags[0];
  const value = tag?.attrs?.[String(name).toLowerCase()];
  return value === undefined ? null : value;
}

/** Every live `<meta name="source-repo">` element, in document order. */
export function sourceRepoTags(html) {
  return scanHtml(html)
    .tags.filter((t) => t.name === "meta" && (t.attrs.name ?? "").trim().toLowerCase() === "source-repo")
    .map((t) => ({ ...t, content: (t.attrs.content ?? "").trim() }));
}

/**
 * What this page says about which repo backs it.
 *
 * Returns `{ tags, repo, disagrees }`. `repo` is null when there is no tag, and
 * null when the tags DISAGREE -- a page that does not agree with itself cannot
 * say which repo backs it, and picking one is a decision made by document order
 * rather than by the operator. core/src/resolver.ts answers the same question
 * the same way, so the extension and the publisher agree about which pages are
 * resolvable.
 */
export function declaredSourceRepo(html) {
  const tags = sourceRepoTags(html);
  const distinct = new Set(tags.map((t) => t.content.toLowerCase()));
  return { tags, repo: distinct.size === 1 ? tags[0].content : null, disagrees: distinct.size > 1 };
}

/**
 * Where a tag belonging in `<head>` must be inserted, as an offset.
 *
 * In order of preference, and every step of it is a defect that shipped:
 *
 *   after the first live `<head ...>`      the normal case. LIVE: a `<head>`
 *                                          inside a comment is not one.
 *   after the first live `<html ...>`      a page with no head. The parser opens
 *                                          one; the tag lands inside it.
 *   after a leading doctype                a fragment with a doctype. Inserting
 *                                          BEFORE the doctype -- which is what
 *                                          this used to do for every headless
 *                                          page -- puts the page into quirks
 *                                          mode, which changes how a client's
 *                                          site is laid out.
 *   0                                      a bare fragment. Still stamp it,
 *                                          rather than ship a page the extension
 *                                          cannot resolve.
 */
export function headInsertionPoint(html) {
  const text = String(html ?? "");
  const { tags, inert } = scanHtml(text);
  const anchor = tags.find((t) => t.name === "head") ?? tags.find((t) => t.name === "html");
  if (anchor) return anchor.end;
  const doctype = inert.find((span) => /^<!doctype/i.test(text.slice(span.start, span.start + 9)));
  return doctype && text.slice(0, doctype.start).trim() === "" ? doctype.end : 0;
}

/**
 * Remove a tag and the line it sat on, but nothing beyond it -- so stripping and
 * re-inserting produces byte-identical output rather than eating a blank line on
 * every deploy.
 */
export function cutTags(html, spans) {
  const text = String(html ?? "");
  let out = text;
  for (const { start, end } of [...spans].sort((a, b) => b.start - a.start)) {
    let from = start;
    while (from > 0 && (text[from - 1] === " " || text[from - 1] === "\t")) from -= 1;
    let to = end;
    while (text[to] === " " || text[to] === "\t") to += 1;
    if (text[to] === "\r") to += 1;
    if (text[to] === "\n") to += 1;
    out = out.slice(0, from) + out.slice(to);
  }
  return out;
}
