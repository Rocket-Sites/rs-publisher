#!/usr/bin/env node
// Publication-mode and project-name validation. No network, no side effects.
// This is the first thing that runs, because everything after it either builds
// or mutates something.
//
// ARCHITECTURE.md invariant 5: `mode` DEFAULTS TO `public`, and the default is
// declared on the workflow_call input, which is the only place GitHub applies it
// -- when the caller omits the input entirely.
//
// This step therefore still rejects every value that is not exactly `public` or
// `gated`, INCLUDING the empty string. An empty mode is not an omitted mode: it
// is what a caller gets from `mode: ${{ vars.SITE_MODE }}` when the variable was
// never set, and that caller believes they are choosing. Reading "" as `public`
// here would publish a site whose author thought they had restricted it, and it
// would do so silently. A failed run is the cheap outcome; take it.
//
// Nothing in this file ever supplies `gated` as a fallback (invariant 8):
// restriction is only what a caller asked for in writing.

import { createLogger, readExplicit } from "../_lib/io.mjs";
import {
  MODES,
  isValidMode,
  isValidProjectName,
  isValidCustomDomain,
  isValidWranglerVersion,
  ACCESS_INPUT_NAMES,
} from "../_lib/validate.mjs";

export function runValidateInputs({ env, logger }) {
  const mode = readExplicit(env, "MODE");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const customDomain = readExplicit(env, "CUSTOM_DOMAIN").trim();
  const wranglerVersion = readExplicit(env, "WRANGLER_VERSION").trim();

  if (!isValidMode(mode)) {
    logger.error(
      `Invalid publication mode '${mode}'. It must be exactly one of: ${MODES.join(", ")}. ` +
        `'public' publishes a world-readable client site and is what you get by OMITTING the input ` +
        `entirely; 'gated' publishes behind Cloudflare Access for a pre-launch review. An empty ` +
        `value is not the same as an omitted one -- it usually means the caller passed an unset repo ` +
        `variable and believes it is choosing the mode, so the publisher fails here instead of ` +
        `picking for you. Either delete the 'mode:' line or set it to a real value.`
    );
    return 1;
  }
  logger.info(`Publication mode: ${mode}`);

  if (!isValidProjectName(projectName)) {
    logger.error(
      `Invalid Cloudflare Pages project name '${projectName}' -- only lowercase letters, digits and ` +
        `hyphens are allowed. The name is used in Cloudflare API paths and in a JSON body, so a value ` +
        `outside that set is rejected before it reaches either.`
    );
    return 1;
  }

  // A caller that says `public` -- or lets it default -- while also passing
  // access inputs believes it is restricting something that is not restricted.
  // That belief is exactly how an agency shares a URL thinking the client review
  // gate is up. Fail, do not warn.
  //
  // Under a public default this check carries more weight than it used to: it is
  // the guard rail against the one regression the default introduces. Delete the
  // `mode: gated` line from a site that is genuinely in review and this is what
  // stops the next deploy from quietly tearing the gate down, because such a
  // site always still carries client-emails or agency-domain.
  if (mode === "public") {
    const supplied = [
      ["agency-domain", readExplicit(env, "AGENCY_DOMAIN")],
      ["client-domain", readExplicit(env, "CLIENT_DOMAIN")],
      ["client-emails", readExplicit(env, "CLIENT_EMAILS")],
    ].filter(([, value]) => value.trim() !== "");

    if (supplied.length > 0) {
      logger.error(
        `mode: public (stated, or defaulted by omitting the input) was requested together with ` +
          `access input(s) ${supplied
            .map(([name]) => name)
            .join(", ")}. In public mode nothing is restricted, so those values grant nothing and ` +
          `anyone reading the caller workflow would reasonably think the site is still gated. ` +
          `Decide which you mean: keep the site in client review (add mode: gated back), or publish ` +
          `it to the world (clear ${ACCESS_INPUT_NAMES.join(", ")}). Restriction is only ever ` +
          `something you ask for in writing, and this is the publisher refusing to guess that you ` +
          `meant to drop it.`
      );
      return 1;
    }
  }

  // ── the declared custom domain (ARCHITECTURE.md invariant 11) ──────────
  if (customDomain !== "") {
    if (!isValidCustomDomain(customDomain)) {
      logger.error(
        `Invalid custom-domain '${customDomain}'. It must be a bare hostname such as 'client.com' or ` +
          `'www.client.com' -- no scheme, no path, no port, no '@'. The value is compared against what ` +
          `Cloudflare reports for the Pages project and is stamped into the canonical URL of every ` +
          `published page, so anything else produces a live client site advertising a broken canonical.`
      );
      return 1;
    }
    // Invariant 10 refuses a custom domain in gated mode after the project has
    // been read. Declaring one makes the same refusal available here, with no
    // network call and before anything at all has happened -- the caller is
    // telling us in writing that this project answers on a host a Cloudflare
    // Access app over pages.dev cannot cover.
    if (mode === "gated") {
      logger.error(
        `mode: gated was requested together with \`custom-domain: ${customDomain}\`. A Cloudflare ` +
          `Access app covers only the hosts it names, so a gate over the project's pages.dev host ` +
          `would leave this unlaunched site readable at ${customDomain} while the post-deploy check ` +
          `collected its redirect from a hostname no visitor uses. That combination is refused ` +
          `(ARCHITECTURE.md invariant 10). Choose one: publish the site for real (drop 'mode: gated' ` +
          `-- public is the default), or keep it in review and remove both the custom domain and this ` +
          `input until launch. NOTHING HAS BEEN BUILT OR PUBLISHED.`
      );
      return 1;
    }
    logger.info(`Declared custom domain: ${customDomain} (discovery must agree, and the publisher never attaches it)`);
  }

  // ── the one input that reached a third party unvalidated (issue #123) ──
  //
  // `wrangler-version` is interpolated by cloudflare/wrangler-action into
  // `npm install wrangler@<version>`, in the job that holds the agency's
  // Cloudflare API token. That is an npm spec: a git URL or a file path installs
  // arbitrary code there. It is not shell-injectable at the SHA this workflow
  // pins, because upstream builds an argv array -- but that is a property of
  // somebody else's code, and every other caller input is validated here.
  if (!isValidWranglerVersion(wranglerVersion)) {
    logger.error(
      `Invalid wrangler-version '${wranglerVersion}'. It must be an exact version such as '3.114.1', ` +
        `or empty to let the deploy action choose. A range like '^3' is refused on purpose: it is not ` +
        `a pin, and the only reason to name a version is to get the same one twice. Anything else is ` +
        `an npm install specifier running in the job that holds this agency's Cloudflare API token. ` +
        `NOTHING HAS BEEN BUILT OR PUBLISHED.`
    );
    return 1;
  }
  if (wranglerVersion) logger.info(`Wrangler version pinned by the caller: ${wranglerVersion}`);

  logger.info(`Pages project name: ${projectName}`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(runValidateInputs({ env: process.env, logger }));
}
