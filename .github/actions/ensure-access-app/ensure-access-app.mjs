#!/usr/bin/env node
// GATED MODE ONLY. Guarantee a Cloudflare Access application covers the domain
// this site is served at -- the apex AND *.<domain> -- before anything is
// published. No Access app, no publish.
//
// This is the fail-closed half of the inversion. In gated mode the site is an
// unlaunched client site under review, and the failure this prevents is the one
// an agency does not forgive: a client's unfinished site findable by their
// competitors, or by their customers, before launch.
//
// The wildcard is not theoretical hardening. Cloudflare has no setting that
// disables preview deployments outright, so a hash.<project>.pages.dev URL
// created by anyone holding the Pages token bypasses an apex-only app. Covering
// *.<domain> is the mechanism by which an unlaunched site stays unfindable
// (ARCHITECTURE.md invariant 4).
//
// It also refuses the one combination the gate cannot cover: a Pages project
// carrying a custom domain (ARCHITECTURE.md invariant 10). That refusal happens
// here rather than after the deploy because here it costs a failed run, and
// there it would cost a live site with an unprovable gate over it.
//
// This script NEVER deletes an Access app. Removing a gate is the public
// branch's corrective action and has no business in the gated one.

import { createLogger, createOutputs, readExplicit, realSleep } from "../_lib/io.mjs";
import { createCloudflare, appHasWildcard } from "../_lib/cf.mjs";
import { resolveDomain } from "../_lib/domain.mjs";

export const SESSION_DURATION = "24h";

export async function runEnsureAccessApp({ env, logger, outputs, fetchImpl, sleep = realSleep }) {
  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const cf = createCloudflare({ accountId, token, fetchImpl });

  const { domain, readOk, customDomains } = await resolveDomain(cf, projectName, logger);

  // ── no host, no gate (invariant 12, issue #120) ──────────────────────────
  //
  // FIRST, ahead of the custom-domain refusal below, because that refusal reads
  // `customDomains` and a failed read yields an empty one. Evaluating it here
  // would be reading a fact this run never observed: the array is empty because
  // nothing was seen, not because the project carries no domains, and the
  // difference is a client's unlaunched site readable at client.com while the
  // proof collects its 302 on a pages.dev host.
  //
  // This used to be unreachable, because resolveDomain fell back to
  // `<project>.pages.dev` on exactly these two states. In gated mode that means
  // building an Access app over a hostname that, on a global name collision,
  // belongs to a different Cloudflare account.
  if (!domain) {
    logger.error(
      readOk
        ? `The Cloudflare Pages project '${projectName}' has no .subdomain, so there is no host to put ` +
            `a Cloudflare Access gate over. This site is in gated mode and will not publish without a ` +
            `gate: NOTHING HAS BEEN UPLOADED. The project is created by an earlier step in this run, ` +
            `so this usually means that step did not do what it reported -- re-run, and check the ` +
            `project exists in Cloudflare dashboard -> Workers & Pages.`
        : `The Cloudflare Pages project '${projectName}' could not be read, so this run does not know ` +
            `which host to gate, and does not know whether a custom domain is attached to it. Both ` +
            `matter: an Access app covers only the hosts it names. The publisher will NOT fall back ` +
            `to '${projectName}.pages.dev' -- that name is global, and on a collision it belongs to a ` +
            `different Cloudflare account, so the gate would go over a stranger's hostname while this ` +
            `client's unlaunched site went up ungated. NOTHING HAS BEEN UPLOADED and nothing was ` +
            `created. Re-run; if it persists, check the Cloudflare token and account id.`
    );
    return 1;
  }

  // Export the resolved domain IMMEDIATELY, before any create attempt. If the
  // create then fails, the post-deploy verifier must still probe the domain the
  // site is actually served at -- probing a stale name-based domain either
  // green-lights an unprotected site or rolls back a good deployment.
  outputs.set("domain", domain);
  logger.info(`Access domain resolved to ${domain}`);

  // ── invariant 10: a custom domain and gated mode are refused together ────
  // An Access app covers the hosts it names. With client.com attached to this
  // project, a gate over <project>.pages.dev leaves the site readable on
  // client.com while the post-deploy proof collects its 302 on pages.dev and
  // reports the gate proven -- success on a state nobody verified, which is what
  // invariant 2 forbids. Refuse HERE, before the upload, so the run ends with
  // nothing published rather than with an unprovable gate over live content.
  // Nothing is destroyed: the custom domain is the agency's, and removing it is
  // not the publisher's call.
  if (customDomains.length > 0) {
    logger.error(
      `mode: gated was requested, but the Pages project '${projectName}' also answers on ` +
        `${customDomains.join(", ")}. A Cloudflare Access app covers only the hosts it names, so a gate ` +
        `over ${domain} would leave this site readable on ${customDomains[0]} while the post-deploy ` +
        `check proves a gate on a hostname no visitor uses. NOTHING HAS BEEN UPLOADED. Choose one: ` +
        `remove the custom domain from ${projectName} until the site launches, publish it for real ` +
        `(drop 'mode: gated' -- public is the default), or put Cloudflare Access over ` +
        `${customDomains[0]} by hand and accept that this publisher is not what proves it. ` +
        `See ARCHITECTURE.md invariant 10 and issue #34.`
    );
    return 1;
  }

  const found = await cf.findAccessApp(domain);
  if (!found.listOk) {
    // A failed lookup is not evidence that no app exists. Concluding "no app,
    // create one" from it produces duplicate apps; concluding "fine" from it
    // publishes an unlaunched site with an unverified gate.
    logger.error(
      `Could not list Cloudflare Access applications (${found.error}), so whether ${domain} is gated ` +
        `is unknown. This site is in gated mode and will not publish on an unverified gate. Check ` +
        `that the Cloudflare token carries 'Access: Apps and Policies: Edit'.`
    );
    return 1;
  }

  if (found.app) {
    logger.info(`Found existing Access app ${found.app.id} covering ${domain}.`);
    if (!appHasWildcard(found.app, domain)) {
      // Back-fill onto apps created before the wildcard was part of the payload,
      // otherwise every pre-existing site keeps the hash.<name>.pages.dev bypass
      // open. PUT, not PATCH: an API token gets error 10405 on PATCH. PUT
      // preserves the attached policies.
      //
      // 10405 is INHERITED, not measured here (issue #105). Nothing branches on
      // it -- it is the reason for a choice of verb, and the choice is right
      // whether or not the number is -- so it is recorded as unverified rather
      // than dressed up as a fact.
      const payload = {
        name: found.app.name,
        domain: found.app.domain,
        type: found.app.type,
        session_duration: found.app.session_duration,
        self_hosted_domains: [...(found.app.self_hosted_domains ?? [found.app.domain]), `*.${domain}`],
      };
      for (const key of Object.keys(payload)) if (payload[key] == null) delete payload[key];

      const put = await cf.updateAccessApp(found.app.id, payload);
      if (cf.ok(put)) {
        logger.info(`Back-filled *.${domain} onto Access app ${found.app.id} -- preview URLs are gated now.`);
      } else {
        // Non-fatal: the apex gate is already up, so the site is not open to a
        // casual visitor. The preview-URL bypass stays open until this succeeds.
        logger.warning(
          `Could not add *.${domain} to Access app ${found.app.id}: ${cf.firstError(put)}. The apex is ` +
            `still gated, but preview URLs of the form hash.${domain} may not be. Add the wildcard by ` +
            `hand in Cloudflare Zero Trust -> Access -> Applications.`
        );
      }
    }
    outputs.set("app-id", found.app.id);
    return 0;
  }

  logger.info(`No Access app covers ${domain} yet -- creating one.`);
  const payload = {
    name: projectName,
    domain,
    self_hosted_domains: [domain, `*.${domain}`],
    type: "self_hosted",
    session_duration: SESSION_DURATION,
  };

  let lastError = "";
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const created = await cf.createAccessApp(payload);
    const id = created.json?.result?.id;
    if (id) {
      logger.info(`Created Access app ${id} covering ${domain} and *.${domain}.`);
      outputs.set("app-id", id);
      return 0;
    }
    lastError = cf.firstError(created);
    const code = cf.firstErrorCode(created);
    logger.info(`Access app create attempt ${attempt}/3: code=${code} message=${lastError}`);

    if (code === "12130") {
      // Not transient. With the project's REAL subdomain in hand, this means the
      // account does not own the domain -- retrying can never fix it.
      //
      // The CODE is branched on and is inherited from glassdocs; the MESSAGE
      // Cloudflare sends with it has not been measured here (issue #105).
      // Glassdocs words it "does not belong to zone" and the operator message
      // below says "account", which is the more useful thing to tell an agency
      // and is true of the situation either way. Nothing reads the message, so
      // the two wordings cost nothing -- but do not treat either as measured.
      logger.error(
        `Cloudflare says ${domain} does not belong to this account (Access error 12130), so no gate ` +
          `can be created for it. Usually this means a global pages.dev name collision, or the site ` +
          `is wired to the wrong Cloudflare account. NOTHING HAS BEEN PUBLISHED -- this site stays ` +
          `unbuilt rather than going up ungated. Fix: point CLOUDFLARE_ACCOUNT_ID at the account that ` +
          `owns ${domain}, or delete and recreate the Pages project under a free name.`
      );
      return 1;
    }
    await sleep(8000);
  }

  logger.error(
    `Could not create the Cloudflare Access app for ${domain} after 3 attempts (last: ${lastError}). ` +
      `This site is in gated mode, so it will not publish without a gate: nothing has been uploaded ` +
      `and the client's unlaunched site is not on the internet. Re-run once Cloudflare Access is ` +
      `reachable.`
  );
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  const outputs = createOutputs(process.env);
  process.exit(await runEnsureAccessApp({ env: process.env, logger, outputs }));
}
