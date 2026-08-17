#!/usr/bin/env node
// Inject <meta name="source-repo" content="owner/repo"> into every published
// HTML file, REPLACING whatever was there.
//
// The repo a page belongs to is a deploy-time fact, and CI is the only party
// that knows it for certain. A hand-edited (or copy-pasted-from-another-site)
// value in the source would otherwise ship, and that tag is the ONLY mechanism
// the extension has for resolving a live page back to its repo -- get it wrong
// and "open the client's page and chat to edit it" fails with no diagnosable
// cause. It is also what the public post-deploy check reads to decide whether a
// 200 is really this site (ARCHITECTURE.md invariant 7), so the published bytes
// have to be right rather than merely checked.

import fs from "node:fs";
import path from "node:path";
import { createLogger, readExplicit } from "../_lib/io.mjs";
import { walkArtifact, reportRefusals } from "../_lib/walk.mjs";
import { cutTags, headInsertionPoint, sourceRepoTags } from "../_lib/html.mjs";

/**
 * Replace every source-repo tag on the page with this run's, in the place a
 * browser will actually read it.
 *
 * BOTH HALVES USED TO BE REGEXES, AND BOTH WERE WRONG (issues #138, #125):
 *
 *   the anchor was the first TEXTUAL `<head`, so a `<head>` inside a leading
 *     comment took the tag -- and the two legal templates already ship a leading
 *     comment. The page then shipped with no recognition tag in the DOM while
 *     every check reported pass.
 *   the strip required a QUOTED `name="source-repo"`, so an unquoted decoy
 *     survived it, and the browser reads that decoy as the tag.
 *
 * Both now go through _lib/html.mjs, which reads a page the way a browser does.
 */
export function injectInto(html, repo) {
  const tag = `<meta name="source-repo" content="${repo}">`;
  const stripped = cutTags(html, sourceRepoTags(html));
  const at = headInsertionPoint(stripped);
  // at === 0 is a bare fragment with no doctype, no <html> and no <head>. It
  // still gets the tag rather than shipping a page the extension cannot resolve.
  if (at === 0) return `${tag}\n${stripped}`;
  return `${stripped.slice(0, at)}\n  ${tag}${stripped.slice(at)}`;
}

export function runInjectSourceMeta({ env, logger, fs: fsImpl = fs }) {
  const repo = readExplicit(env, "REPO").trim();
  const dir = readExplicit(env, "PUBLISH_DIR");

  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    logger.error(
      `Cannot inject the recognition meta: '${repo}' is not an OWNER/REPO value. Every published ` +
        `page must carry <meta name="source-repo">; without it the extension cannot resolve the page ` +
        `back to its repo and the public post-deploy check has no way to prove the live site is this one.`
    );
    return 1;
  }

  // Refuse BEFORE writing anything (issue #141). This step opens every page it
  // walks for writing, so a symbolic link walked as a file is a write THROUGH
  // it, into a path outside the publish directory. Nothing has been written yet
  // at this point, and nothing will be.
  const { files: regular, refused } = walkArtifact(dir);
  if (reportRefusals(refused, (file, line, msg) => logger.errorAt(path.relative(dir, file) || file, line, msg)) > 0) {
    logger.error(
      `The publish directory contains ${refused.length} entr${refused.length === 1 ? "y" : "ies"} that ` +
        `${refused.length === 1 ? "is" : "are"} not a regular file. Nothing was stamped and nothing was ` +
        `uploaded.`
    );
    return 1;
  }

  const files = regular.filter((f) => /\.html?$/i.test(f));
  for (const file of files) {
    const before = fsImpl.readFileSync(file, "utf8");
    const after = injectInto(before, repo);
    if (after !== before) fsImpl.writeFileSync(file, after);
  }
  logger.info(`Stamped <meta name="source-repo" content="${repo}"> into ${files.length} page(s).`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(runInjectSourceMeta({ env: process.env, logger }));
}
