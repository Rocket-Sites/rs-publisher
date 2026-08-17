#!/usr/bin/env node
// PUBLIC MODE ONLY. Resolve the domain and remove any Cloudflare Access app
// gating it, before the deploy.
//
// `mode: public` is the caller's explicit declaration that this client site is
// world-readable and launched. An Access app still covering the domain --
// typically because the site was in client review last week -- silently defeats
// that, and the client is paying for the site to be findable. So the gate is
// removed, loudly.
//
// Best effort by design: with no Access scope on the token this can only warn,
// and the post-deploy check is the backstop that actually decides. This script
// never rolls anything back and never deletes a Pages project; those are the
// gated branch's corrective actions and they cannot un-gate anything.

import { createLogger, createOutputs, readExplicit } from "../_lib/io.mjs";
import { createCloudflare } from "../_lib/cf.mjs";
import { resolveDomain } from "../_lib/domain.mjs";

// An apex-only app and a wildcard app can both cover the same domain. Bounded
// so a pathological account cannot spin here.
export const MAX_APPS_REMOVED = 5;

export async function runRemoveAccessGate({ env, logger, outputs, fetchImpl }) {
  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const cf = createCloudflare({ accountId, token, fetchImpl });

  logger.notice(
    `PUBLIC MODE -- this site publishes with no Cloudflare Access gate. That is an explicit ` +
      `'mode: public' in the caller workflow, which is how a Rocket Site launches.`
  );

  const { domain, readOk } = await resolveDomain(cf, projectName, logger);
  // No host means nothing to look up, and the alternative -- guessing
  // `<project>.pages.dev` -- would have this step DELETE AN ACCESS APP belonging
  // to whatever account owns that name on a collision (invariant 12, issue
  // #120). Warn and continue: gate removal is best effort by design, and the
  // post-deploy proof is the backstop that actually decides.
  if (!domain) {
    logger.warning(
      readOk
        ? `The Cloudflare Pages project '${projectName}' has no .subdomain, so this step has no host ` +
            `to check for a leftover Access gate. If the site is still locked after this run, the ` +
            `post-deploy check will say so and name the application to remove by hand.`
        : `The Cloudflare Pages project '${projectName}' could not be read, so this step does not know ` +
            `which host to check for a leftover Access gate, and will not guess one. If the site is ` +
            `still locked after this run, the post-deploy check will say so and name the application ` +
            `to remove by hand.`
    );
    return 0;
  }
  outputs.set("domain", domain);

  let removed = 0;
  for (; removed < MAX_APPS_REMOVED; removed += 1) {
    const found = await cf.findAccessApp(domain);
    if (!found.listOk) {
      logger.warning(
        `Could not list Cloudflare Access applications (${found.error}), so a leftover gate on ` +
          `${domain} cannot be removed automatically -- the token may lack 'Access: Apps and ` +
          `Policies'. If the site is still locked after this run, the post-deploy check will say so ` +
          `and name the app to remove by hand.`
      );
      return 0;
    }
    if (!found.app) {
      if (removed === 0) logger.info(`No Access app gates ${domain} -- nothing to remove.`);
      else logger.info(`Removed ${removed} Access app(s) covering ${domain}. None remain.`);
      return 0;
    }
    logger.warning(
      `Removing Access app ${found.app.id} ('${found.app.name}') which gates ${domain}. This site is ` +
        `launched, so a gate here would leave a live client site locked.`
    );
    const del = await cf.deleteAccessApp(found.app.id);
    if (!cf.ok(del)) {
      logger.warning(
        `Failed to delete Access app ${found.app.id}: ${cf.firstError(del)}. The post-deploy check ` +
          `will fail the run if the site stays locked.`
      );
      return 0;
    }
  }

  // ── the cap was reached. ASK, do not infer (issue #109) ────────────────
  //
  // This used to be an unconditional "and there may be more", derived from the
  // removal count hitting the ceiling -- so removing EXACTLY the cap, with none
  // left, was indistinguishable from exceeding it. Reproduced: five apps, five
  // deleted, zero remaining, and the operator was told the site may still be
  // gated to someone. That sentence lands on the PUBLIC path, where it means the
  // launch may not have completed, and the only way to check it is to go and
  // look in the Cloudflare dashboard -- the manual step this publisher exists to
  // remove, on the run where an agency is most anxious.
  //
  // One more list answers it exactly, and this is invariant 1: the loop is
  // bounded because an account could be pathological, but a bound is not
  // evidence about what is left. Asking costs one read and the answer is a fact.
  const remaining = await cf.findAccessApp(domain);
  if (!remaining.listOk) {
    logger.warning(
      `Removed ${MAX_APPS_REMOVED} Access apps covering ${domain}, and whether any remain could not be ` +
        `established (${remaining.error}). That is not the same as knowing more are there. If the site ` +
        `is still locked after this run, the post-deploy check will say so and name the app to remove.`
    );
    return 0;
  }
  if (remaining.app) {
    logger.warning(
      `Removed ${MAX_APPS_REMOVED} Access apps covering ${domain} and app ${remaining.app.id} ` +
        `('${remaining.app.name}') STILL gates it. This step stops at ${MAX_APPS_REMOVED} so a ` +
        `pathological account cannot spin here. Remove the rest in Cloudflare Zero Trust -> Access -> ` +
        `Applications, or re-run this deploy.`
    );
    return 0;
  }
  logger.info(`Removed ${MAX_APPS_REMOVED} Access apps covering ${domain}. None remain.`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  const outputs = createOutputs(process.env);
  process.exit(await runRemoveAccessGate({ env: process.env, logger, outputs }));
}
