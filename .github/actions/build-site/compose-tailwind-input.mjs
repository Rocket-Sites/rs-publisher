#!/usr/bin/env node
// Compose the Tailwind build input, and print its path (issue #167).
//
// Under Tailwind v3 the publisher pointed the CLI straight at a site's
// `tailwind.css` and the CLI picked up `tailwind.config.cjs` from the working
// directory and EXECUTED IT. There is no config module any more: v4's theme is
// CSS, and the values come out of `rocket-site.json`, which is data. This step
// is what joins the two, and it is deliberately the only place in the build that
// reads anything out of the site repository other than bytes to copy.
//
// WHERE THE COMPOSED FILE GOES, and it is the load-bearing detail.
//
// Tailwind 4 resolves `@import "tailwindcss"` by walking up from the INPUT FILE
// looking for `node_modules`. Not from the working directory, and not from the
// CLI's own location. Measured on 4.3.3: an input in the system temp directory
// fails with `Can't resolve 'tailwindcss' in /private/tmp/...` however the CLI
// is invoked. So the caller installs the CLI into a scratch directory, passes
// that directory as RS_TAILWIND_HOME, and the composed file is written inside
// it -- where the resolution succeeds by construction rather than by luck.
//
// That directory is outside both the site checkout and the publish directory.
// Inside the site directory it would be a file the next `rsync` had to know
// about; inside the publish directory it would be UPLOADED to the client's site.
//
// The site's own `tailwind.css` is READ AND SPLICED IN as text rather than
// `@import`ed, because `@import "tailwindcss"` resolves against the directory of
// the file that writes it and a client's site repository has no `node_modules`.
// _lib/theme.mjs carries the measurement and the consequences; the one that
// matters here is that every `@source` must be an ABSOLUTE path passed in from
// this side, so a relative one inside the spliced text cannot resolve against
// the wrong directory.
//
// A site with no `tailwind.css` still publishes: it gets the framework and its
// own brand theme and nothing else, which is what the pre-#167 baseline
// directives amounted to.

import fs from "node:fs";
import path from "node:path";
import { createLogger, readExplicit } from "../_lib/io.mjs";
import { buildInput } from "../_lib/theme.mjs";

export function runComposeInput({ env, logger }) {
  const siteDir = readExplicit(env, "SITE_DIR");
  const publishDir = readExplicit(env, "PUBLISH_DIR");

  const inputPath = path.resolve(siteDir, "tailwind.css");
  let templateCss = "";
  if (fs.existsSync(inputPath)) {
    templateCss = fs.readFileSync(inputPath, "utf8");
  } else {
    logger.info("No tailwind.css in the site source -- building the framework and this site's theme only.");
  }

  // rocket-site.json is optional and a malformed one is a hard failure rather
  // than a silent fallback. A site whose brand config cannot be read is a site
  // that would publish in the template's colours under the client's name, and
  // nobody would see it until the client did.
  const configPath = path.resolve(siteDir, "rocket-site.json");
  let config = {};
  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    } catch (err) {
      logger.error(
        `rocket-site.json could not be parsed (${err.message}). It carries this site's brand tokens, so ` +
          `building past it would publish the template's colours under the client's name. Fix the JSON.`,
      );
      return 1;
    }
  } else {
    logger.info("No rocket-site.json in the site source -- building with the template's own theme only.");
  }

  const { css, problems } = buildInput({
    templateCss,
    brand: config.brand,
    brandDark: config.brand_dark,
    // The ASSEMBLED pages, so the purge is judged on the bytes that will be
    // served rather than on the source they were copied from.
    sources: [path.resolve(publishDir)],
  });

  if (problems.length > 0) {
    for (const problem of problems) logger.error(problem);
    logger.error(
      `Refusing to build. A brand token is written straight into the stylesheet this client's visitors ` +
        `load, so a value that is not the shape it claims to be is not something to escape or guess at.`,
    );
    return 1;
  }

  // Inside the directory the CLI was installed into, so `@import "tailwindcss"`
  // resolves. See the header: this is not a cosmetic choice of temp directory,
  // and a build.css in os.tmpdir() fails the build outright.
  const home = env.RS_TAILWIND_HOME;
  if (!home || !fs.existsSync(path.join(home, "node_modules", "tailwindcss"))) {
    logger.error(
      `RS_TAILWIND_HOME must name a directory containing node_modules/tailwindcss (got ${home ?? "nothing"}). ` +
        `Tailwind 4 resolves '@import "tailwindcss"' by walking up from the input file, so a composed input ` +
        `written anywhere else fails with "Can't resolve 'tailwindcss'".`,
    );
    return 1;
  }
  const dir = fs.mkdtempSync(path.join(home, "rs-tailwind-"));
  const composed = path.join(dir, "build.css");
  fs.writeFileSync(composed, css);
  // stdout is the answer, so the shell can capture it. Everything else the step
  // has to say goes through the logger, which writes to stderr.
  process.stdout.write(`${composed}\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // stderr, not stdout: stdout carries the composed file's path and the shell
  // captures it. Actions reads annotations off either stream.
  const logger = createLogger({ stream: process.stderr });
  process.exit(runComposeInput({ env: process.env, logger }));
}
