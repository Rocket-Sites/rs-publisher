#!/usr/bin/env node
// Write the publisher's `_headers` into the artifact (issue #260).
//
// Runs AFTER the rsync assembly and BEFORE the artifact guard, and both halves
// of that position are load-bearing.
//
// After the rsync, because the deny-list is what keeps a site repository's own
// `_headers` out of the upload directory and that has not changed. Before the
// guard, because the guard's whole model is that the published bytes are the
// whole site: a file written after it would change what a visitor is served
// while every rule the guard ran was still true of a directory that no longer
// exists. That is the shape CLAUDE.md hard rule 1 refuses a Pages Function for,
// and shipping it in the publisher would be the same hole with our name on it.
//
// It REFUSES rather than overwrites, which is the difference between this and
// the robots.txt the stamping step replaces with a warning. A `_headers` in the
// publish directory at this moment did not come through the rsync -- that path
// is excluded by name -- so it was written by a build step, and a build step
// that authors edge configuration is a thing to fail on rather than to quietly
// win a race with. Overwriting would also make the two cases indistinguishable:
// the guard would see the publisher's bytes either way and nobody would learn
// that the site repository had tried.
//
// Nothing here is client input. The bytes are a constant in _lib/headers.mjs and
// the only thing this file decides is where they land.

import fs from "node:fs";
import path from "node:path";
import { createLogger, readExplicit } from "../_lib/io.mjs";
import { PAGES_HEADERS, HEADERS_ENTRY, SECURITY_HEADERS } from "../_lib/headers.mjs";

export function runWritePagesHeaders({ env, logger, fsImpl = fs }) {
  const dir = readExplicit(env, "PUBLISH_DIR");

  if (!fsImpl.existsSync(dir)) {
    logger.error(`Publish directory '${dir}' does not exist, so there is nothing to write the site's headers into.`);
    return 1;
  }

  const at = path.join(dir, HEADERS_ENTRY);
  if (fsImpl.existsSync(at)) {
    logger.error(
      `A ${HEADERS_ENTRY} is already in the publish directory, and the publisher did not put it there. ` +
        `Cloudflare Pages reads it from the root of the uploaded directory, where it sets or strips the ` +
        `response headers every visitor gets, so it is configuration of the serving edge rather than an ` +
        `asset. It is excluded from the assembly by name, which means this one was authored by a build ` +
        `step. The publisher writes this file itself, from a constant, on every site. Delete it from the ` +
        `site repo and from anything that generates into the publish directory.`
    );
    return 1;
  }

  fsImpl.writeFileSync(at, PAGES_HEADERS);
  logger.info(
    `Wrote ${HEADERS_ENTRY} with ${SECURITY_HEADERS.length} security header(s) for every path: ` +
      `${SECURITY_HEADERS.map(([name]) => name).join(", ")}.`
  );
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(runWritePagesHeaders({ env: process.env, logger }));
}
