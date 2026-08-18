#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════
// Post-deploy proof, in both directions. This is the security-critical surface
// of the whole product, and it is the file most likely to be broken by someone
// making the two branches look symmetric.
//
// ┌──────────────┬──────────────────────────────┬─────────────────────────────┐
// │              │ gated (unlaunched site)      │ public (live site)          │
// ├──────────────┼──────────────────────────────┼─────────────────────────────┤
// │ desired      │ 3xx to *.cloudflareaccess    │ 200 AND the body carries    │
// │ state proven │ .com                         │ this repo's source-repo meta│
// │ undesired    │ 200 AND the body carries     │ 3xx to Access, or an Access │
// │ state proven │ this repo's source-repo meta │ app covering the domain     │
// │ nothing      │ proves neither: ask the      │ proves neither: ask the     │
// │ served       │ Access API                   │ Access + deployments APIs   │
// │ corrective   │ roll production back; delete │ REMOVE THE ACCESS APP.      │
// │ action       │ the project only if this run │ Never roll back, never      │
// │              │ created it and there is      │ delete the project.         │
// │              │ nothing to roll back to      │                             │
// └──────────────┴──────────────────────────────┴─────────────────────────────┘
//
// The corrective action is NOT symmetric, and that is the specific danger.
// Rolling back a deployment can never un-gate a site, because the gate lives in
// Access configuration and not in the deployment: a publisher that reflexively
// rolls back on a failed public check replaces a locked live site with a locked
// live site running yesterday's content, which is strictly worse and looks like
// a fix. Equally, deleting an Access app is never a remedy for exposure.
//
// Two incidents from the reference implementation are encoded here:
//
//   glassdocs#67 -- treating every non-3xx as "roll back" collapsed three
//     genuinely different outcomes into one, and the only case that ever fired
//     the rollback was a first deploy, which is exactly the case where there was
//     nothing to roll back to and the gate had been up the whole time. Proven
//     gated, proven exposed, and nothing-served-at-all are three states.
//   glassdocs#71 -- "we took an action" is not "the site stopped serving". A
//     rollback whose target build is also ungated has fixed nothing, and the
//     rollback call itself can fail. Act, then re-probe, then report which
//     actually happened.
// ═══════════════════════════════════════════════════════════════════════

import { createLogger, readExplicit, realSleep, seconds } from "../_lib/io.mjs";
import {
  createCloudflare,
  probe,
  isRedirect,
  redirectHost,
  redirectsToAccessLogin,
  accessRedirectKind,
  describeObservation,
  bodyDeclaresRepo,
} from "../_lib/cf.mjs";
import { resolveDomain, reconcileCustomDomains } from "../_lib/domain.mjs";
import { isValidMode, MODES } from "../_lib/validate.mjs";

/**
 * The mode-to-corrective-action mapping, stated once as data so a test can
 * assert it and a reader can check it without tracing branches. If you add an
 * action to one of these lists, you are changing the safety contract.
 */
export const CORRECTIVE_ACTIONS = Object.freeze({
  gated: Object.freeze(["rollback-production", "delete-pages-project"]),
  public: Object.freeze(["delete-access-app"]),
});

const ZERO_TRUST_PATH = "Cloudflare dashboard -> Zero Trust -> Access -> Applications";
/** Named verbatim, because an agency has to find it in a permission dropdown. */
const ACCESS_PERMISSION = "Access: Apps and Policies";
const PAGES_PATH = "Cloudflare dashboard -> Workers & Pages";

function timings(env, firstDeploy) {
  // Test seam only. Nothing sets these in CI or in production; the fallbacks
  // below are the shipped values. Without the seam, the suite spends five
  // minutes sleeping per case and gets deleted, which is the same as having no
  // suite at all.
  //
  // A project created seconds ago answers 522 at the edge for minutes: measured
  // on a real first deploy at 05:02:56Z created, still 522 at 05:04:12Z, serving
  // correctly by ~05:07Z. A 55 second window failed a deploy whose gate was up
  // the whole time.
  return {
    settle: seconds(env, "VERIFY_SETTLE_SECONDS", 15),
    budget: seconds(env, "VERIFY_BUDGET_SECONDS", firstDeploy ? 300 : 60),
    poll: seconds(env, "VERIFY_POLL_SECONDS", 10),
    reprobe: seconds(env, "VERIFY_REPROBE_SECONDS", 30),
  };
}

/**
 * Poll to a DEADLINE rather than for a fixed number of attempts, and judge on
 * the FINAL observation. An early 200 in gated mode can be Access-policy
 * propagation lag; an early 522 in public mode can be a project that has not
 * reached the edge yet. Neither first look is the answer.
 */
async function pollToDeadline(ctx, isProof, domain = ctx.domain) {
  const { logger, sleep, now, fetchImpl, timing } = ctx;
  logger.info(`Waiting ${timing.settle}s for the deployment to propagate...`);
  await sleep(timing.settle * 1000);

  const deadline = now() + timing.budget * 1000;
  let attempt = 0;
  let last = { status: "000", body: "" };
  for (;;) {
    attempt += 1;
    last = await probe(`https://${domain}`, { fetchImpl });
    logger.info(`verify attempt ${attempt}: https://${domain} -> HTTP ${last.status}`);
    if (isProof(last)) return { ...last, proven: true };
    if (now() >= deadline) return { ...last, proven: false };
    await sleep(timing.poll * 1000);
  }
}

/** Re-probe after a corrective action. Returns the final observation. */
async function reprobe(ctx, isFixed, domain = ctx.domain) {
  const { logger, sleep, now, fetchImpl, timing } = ctx;
  await sleep(timing.settle * 1000);
  const deadline = now() + timing.reprobe * 1000;
  let last = { status: "000", body: "" };
  for (;;) {
    last = await probe(`https://${domain}`, { fetchImpl });
    logger.info(`post-action probe: https://${domain} -> HTTP ${last.status}`);
    if (isFixed(last)) return { ...last, fixed: true };
    if (now() >= deadline) return { ...last, fixed: false };
    await sleep(timing.poll * 1000);
  }
}

// ─────────────────────────────────────────────────────────────────────────
// GATED
// ─────────────────────────────────────────────────────────────────────────
async function verifyGated(ctx) {
  const { logger, cf, domain, projectName, repo, createdHere, customDomains, timing } = ctx;

  // Invariant 10. ensure-access-app already refused this before the upload, so
  // reaching here means the domain was attached DURING the run -- rare, and
  // exactly the kind of race a post-deploy check exists for. The gate cannot be
  // proven on a host the Access app does not name, and an unprovable gate is not
  // a proven exposure either: fail, destroy nothing, and say which host is the
  // problem. Rolling back would not remove the custom domain.
  if (customDomains.length > 0) {
    logger.error(
      `Cannot prove the gate on '${projectName}': it is gated at ${domain}, but it also answers on ` +
        `${customDomains.join(", ")}, which the Access app does not cover. A 302 on ${domain} would ` +
        `say nothing about ${customDomains[0]}, so this run reports NO PROOF rather than a gate it did ` +
        `not verify. Nothing was rolled back and nothing was deleted. Remove the custom domain while ` +
        `the site is in review, or drop 'mode: gated' and publish it. ARCHITECTURE.md invariant 10.`
    );
    return 1;
  }

  // Invariant 1, in the form issue #102 showed it has to be stated: a redirect
  // is proof of a gate only when it goes TO the gate. The predicate is the same
  // helper the public branch uses, because the two branches asking this question
  // differently is what produced "Gate confirmed" over an ungated site.
  const final = await pollToDeadline(ctx, redirectsToAccessLogin);
  if (final.proven) {
    // Which shape of Access redirect it is decides whether it stands alone
    // (issue #121). A Location naming the account's `*.cloudflareaccess.com`
    // team host is one the site's origin cannot produce. A Location on the
    // PROTECTED HOST's own `/cdn-cgi/access/login` path is one the origin can
    // choose -- a `_redirects` file of one line makes an entirely ungated
    // project answer it -- so the Access API, which the site cannot write to,
    // has to agree before this run reports a gate.
    if (accessRedirectKind(final) === "team-host") {
      logger.info(
        `Gate confirmed -- an unauthenticated request to https://${domain} answered ` +
          `${describeObservation(final)}, which is this account's Cloudflare Access team host. This ` +
          `unlaunched site is not readable by the public.`
      );
      return 0;
    }

    const corroborating = await cf.findAccessApp(domain);
    if (corroborating.listOk && corroborating.app) {
      logger.info(
        `Gate confirmed -- an unauthenticated request to https://${domain} answered ` +
          `${describeObservation(final)}, which is the Cloudflare Access login path, and Access app ` +
          `${corroborating.app.id} covers the domain. This unlaunched site is not readable by the ` +
          `public. (The redirect alone would not have been enough: that path is served on the ` +
          `protected host, so a redirect rule in the site itself could imitate it.)`
      );
      return 0;
    }
    logger.error(
      `https://${domain} answered ${describeObservation(final)}, which LOOKS like the Cloudflare ` +
        `Access login -- but that path is served on this site's own host, so a redirect configured in ` +
        `the site itself produces exactly the same observation, and ` +
        `${corroborating.listOk ? `NO Access application covers ${domain}` : `the Access configuration could not be read (${corroborating.error})`}. ` +
        `This run will not report a gate it cannot corroborate against the Access API: an unlaunched ` +
        `client site that only appears to be gated is the worst outcome this publisher has. Nothing ` +
        `was rolled back and nothing was deleted. Check for a _redirects file in the site repo, and ` +
        `check ${ZERO_TRUST_PATH}.`
    );
    return 1;
  }

  // PROVEN EXPOSED means what the table at the top of this file says it means:
  // "200 WITH CONTENT SERVED". Not a bare 200 (issue #119).
  //
  // This is the only branch in the publisher that destroys anything, and it used
  // to fire on the status alone, without ever reading the body -- the exact
  // evidence invariant 7 says is not proof, applied to the one branch that can
  // roll an agency's production back or delete their Pages project. Everything
  // that answers 200 without being this client's site would trigger it: a
  // Cloudflare placeholder page on a project whose first deploy has not reached
  // the edge (which is a FIRST DEPLOY, precisely when project-created-here is
  // true and the corrective action is deletion), an Access-branded "you do not
  // have permission" page (which the public branch forty lines away names
  // explicitly as an HTTP 200 and a lock), and a stale unrelated project on a
  // colliding pages.dev name -- this fleet already has one. In each case the
  // site was gated the whole time, and the operator was told to go and delete
  // the project by hand.
  //
  // So the same predicate the public branch uses decides it here: the body
  // carries this repo's source-repo meta, or nothing was proven and nothing is
  // destroyed.
  const servedThisSite = final.status === "200" && bodyDeclaresRepo(final.body, repo);
  if (servedThisSite) {
    return await gatedProvenExposed(ctx);
  }

  // ── NOTHING PROVEN ─────────────────────────────────────────────────────
  // Nothing this run can recognise reached anyone, so nothing of this site
  // leaked -- and nothing proved the gate either. This is emphatically NOT
  // grounds for a destructive action; it is grounds for asking the Access API,
  // which knows the configuration regardless of whether the edge has started
  // serving.
  //
  // A 3xx that is not the Access login lands here too (issue #102). It is a
  // site-level redirect from an origin Access did not intercept, which is
  // evidence AGAINST the gate rather than for it -- but no content was served,
  // so it is not proven exposure either, and the Access API is what decides.
  const observed = describeObservation(final);
  const unrecognised200 = final.status === "200";
  logger.info(
    unrecognised200
      ? `https://${domain} answered HTTP 200, but the body does not carry ` +
          `<meta name="source-repo" content="${repo}">, so what answered is NOT this site: a Cloudflare ` +
          `placeholder page, an Access error page (which is exactly this -- HTTP 200, and a lock), or a ` +
          `different project answering on this name. A bare 200 is not proof of exposure, and this ` +
          `branch destroys nothing on it. Asking the Access API, which is authoritative and does not ` +
          `wait on edge propagation.`
      : isRedirect(final.status)
        ? `https://${domain} answered ${observed} within ${timing.budget}s. That is the site's own ` +
            `redirect and NOT the Access login, so it proves nothing about the gate -- but nothing was ` +
            `served to anyone either. Asking the Access API, which is authoritative and does not wait ` +
            `on edge propagation.`
        : `No Access redirect within ${timing.budget}s (last ${observed}), and nothing was served ` +
            `to anyone either. Asking the Access API, which is authoritative and does not wait on edge ` +
            `propagation.`
  );

  const found = await cf.findAccessApp(domain);
  if (!found.listOk) {
    // "We could not look" and "there is nothing there" call for completely
    // different fixes, and blurring them is how an agency reads a token-scope
    // problem as a missing gate.
    logger.error(
      `Could not READ the Access configuration for ${domain} (${found.error}) -- this is not the same ` +
        `as finding no gate. The Cloudflare token may lack 'Access: Apps and Policies'. The edge did ` +
        `not prove one either (last ${observed}), so the gate is unverified in both ` +
        `directions. The deployment for '${projectName}' is left in place and nothing was destroyed; ` +
        `re-run with a correctly scoped token before sharing the URL.`
    );
    return 1;
  }

  if (found.app) {
    const policies = await cf.listAllPolicies(found.app.id);
    if (!policies.listOk) {
      logger.error(
        `Access app ${found.app.id} covers ${domain}, but its policies could not be READ ` +
          `(${policies.error}) -- that is not the same as finding none. Nothing was destroyed. ` +
          `Re-run before sharing the URL.`
      );
      return 1;
    }
    if (policies.policies.length > 0) {
      // The glassdocs#67 case. A fresh project answers 522 for minutes; failing
      // here used to kill a perfectly good deploy and then try to delete it.
      //
      // A NON-ACCESS REDIRECT lands here too, and it is a weaker position than
      // 522: the origin answered, so Access did not intercept that request. No
      // content was served, so nothing is proven exposed and nothing may be
      // destroyed -- but the operator is told exactly what was seen rather than
      // being read the propagation sentence, because the likeliest reading is
      // that the gate had not taken effect yet and the NEXT request may be
      // served. This is a recorded decision, not an oversight: the Access API is
      // authoritative about configuration, and failing a deploy over
      // propagation lag is the incident glassdocs#67 already paid for.
      logger.warning(
        unrecognised200
          ? `https://${domain} answered HTTP 200 with a body that is not this site's content, and ` +
              `Access app ${found.app.id} covers the domain with ${policies.policies.length} ` +
              `policy(ies). That is what an Access "you do not have permission" page looks like from ` +
              `an unauthenticated client, so the gate is doing its job. Nothing was rolled back and ` +
              `nothing was deleted. OPEN https://${domain} IN A PRIVATE WINDOW BEFORE SHARING THE ` +
              `URL: if the client's site loads, the gate is not up whatever the configuration says.`
          : isRedirect(final.status)
          ? `https://${domain} answered ${observed}, which came from the site's own origin and NOT ` +
              `from Cloudflare Access -- so this run did not prove the gate at the edge. Access app ` +
              `${found.app.id} does cover the domain, with ${policies.policies.length} policy(ies), ` +
              `and the API is authoritative about configuration, so the deploy is allowed to stand ` +
              `and nothing was destroyed. Most likely the gate had not taken effect when this ran. ` +
              `OPEN https://${domain} IN A PRIVATE WINDOW BEFORE SHARING THE URL: if it loads, the ` +
              `site is not gated, whatever the configuration says.`
          : `https://${domain} did not prove the gate at the edge within ${timing.budget}s (last ` +
              `${observed}), but Access app ${found.app.id} covers it with ${policies.policies.length} ` +
              `policy(ies). The gate IS configured and applies the moment the site is reachable. ` +
              `Confirm the site loads once propagation completes.`
      );
      return 0;
    }
    // Zero policies is an UNPROVEN gate, not a proved one, and sync-access-
    // policies.mjs now says the same (issue #219). It used to say the opposite,
    // citing this branch as the reason: "an Access app with zero policies denies
    // everyone -- which post-deploy-verify.mjs already relies on". This branch
    // has never relied on that. It is reachable now only when the app was
    // emptied outside a deploy, because a zero-grant sync fails before the
    // upload; the verdict is unchanged, and it is worth stating that the two
    // steps agree rather than leaving the next reader to discover they did not.
    logger.error(
      `Access app ${found.app.id} covers ${domain} but has NO policies, so it gates everyone ` +
        `including the client and proves nothing about this deploy. No content of this site was ` +
        `served to anyone (last ${observed}), so the deployment is left in place and nothing was ` +
        `destroyed. Fix the policies and re-run before sharing the URL.`
    );
    return 1;
  }

  logger.error(
    `No Cloudflare Access app covers ${domain}, and the edge did not prove a gate either (last ` +
      `${observed}). No content of this site was served to anyone yet, so the deployment is left in ` +
      `place and nothing was destroyed -- but this unlaunched client site will be PUBLIC the moment ` +
      `the edge catches up. Re-run this deploy to create the gate, and do NOT share the URL until a ` +
      `run reports the gate confirmed.`
  );
  void createdHere;
  return 1;
}

/**
 * PROVEN EXPOSED. Content was served to an unauthenticated request for the whole
 * window. This is the only branch in the entire publisher that destroys
 * anything, and it exists only in gated mode.
 */
async function gatedProvenExposed(ctx) {
  const { logger, cf, domain, projectName, createdHere, timing } = ctx;

  logger.error(
    `https://${domain} SERVED CONTENT to an unauthenticated request (HTTP 200) for ${timing.budget}s. ` +
      `This is an unlaunched client site with no gate in front of it. Failing closed and taking it ` +
      `down.`
  );

  const deployments = await cf.listDeployments(projectName);
  // Index 1, not 0: index 0 is the deployment this run just made.
  const previous = (deployments.json?.result ?? []).filter(
    (d) => d?.environment === "production" && (d?.latest_stage?.status ?? "") === "success"
  )[1]?.id;

  if (previous) {
    // The exposed deployment IS the active production one, and Cloudflare
    // refuses to DELETE that (error 8000034) even with ?force=true. Rolling
    // production back to the previous good build is the supported way to stop
    // serving it. 8000034 is inherited and unverified here (issue #105);
    // nothing branches on it, it is the reason a rollback is used instead of a
    // delete, and that choice stands whatever the number turns out to be.
    const rb = await cf.rollback(projectName, previous);
    if (cf.ok(rb)) {
      logger.info(
        `Rolled production back to ${previous}. If that build is also ungated the site is still ` +
          `exposed -- the re-probe below says which.`
      );
    } else {
      logger.error(
        `ROLLBACK FAILED (${cf.firstError(rb)}) -- the exposed deployment is STILL LIVE at ` +
          `https://${domain}. Take it down by hand NOW: ${PAGES_PATH} -> ${projectName}.`
      );
    }
  } else if (createdHere === "true") {
    // Nothing to roll back to, so deleting is the only way to stop serving --
    // and it is defensible ONLY because this run created the project, so the
    // account returns to the state it was in before the deploy. Anything less
    // certain than that takes the branch below and destroys nothing.
    logger.error(
      `No previous deployment to roll back to, and this run created '${projectName}'. Deleting it, ` +
        `which restores the account to its prior state.`
    );
    const del = await cf.deleteProject(projectName);
    if (cf.ok(del)) {
      logger.info(`Deleted Pages project '${projectName}'. Fix the Access gate, then re-run to recreate it.`);
    } else {
      logger.error(
        `DELETE FAILED (${cf.firstError(del)}) -- https://${domain} is STILL SERVING an unlaunched ` +
          `client site publicly. Delete it by hand NOW: ${PAGES_PATH} -> ${projectName} -> Settings ` +
          `-> Delete project.`
      );
    }
  } else {
    logger.error(
      `No previous successful production deployment to roll back to, and this run did NOT create ` +
        `'${projectName}' -- so removing it is not the publisher's call to make; it may be a project ` +
        `this agency has been using for something else. NOTHING WAS DESTROYED and the exposed site ` +
        `is STILL LIVE. Take it down manually NOW: ${PAGES_PATH} -> ${projectName}.`
    );
  }

  // Did that actually close the exposure? Reporting the action as if it were the
  // outcome is the same conflation this whole step exists to avoid.
  const after = await reprobe(ctx, (r) => r.status !== "200");
  if (after.fixed) {
    logger.info(
      `Exposure closed -- https://${domain} no longer serves content to an unauthenticated request ` +
        `(HTTP ${after.status}). The deploy still FAILED: fix the Access gate for ${domain} before ` +
        `redeploying.`
    );
  } else {
    logger.error(
      `STILL EXPOSED -- https://${domain} is SERVING an unlaunched client site to the public right ` +
        `now, after the action above. Either that action failed or the build it fell back to is ` +
        `ungated too. Take the site down by hand IMMEDIATELY: ${PAGES_PATH} -> ${projectName} -> ` +
        `Settings -> Delete project. Do not redeploy until the Access app for ${domain} exists with ` +
        `at least one policy.`
    );
  }
  return 1;
}

// ─────────────────────────────────────────────────────────────────────────
// PUBLIC
// ─────────────────────────────────────────────────────────────────────────

/**
 * A 3xx to another host THIS PROJECT SERVES is not a lock (invariant 11).
 * `www.client.com` 301ing to `client.com` is the ordinary shape of a launched
 * site, and a proof that read every redirect as an Access login would fail the
 * launch deploy of every agency that set one up. A redirect anywhere else --
 * cloudflareaccess.com above all -- stays exactly as suspicious as it was.
 */
function redirectsToSibling(observation, serving, from) {
  if (!isRedirect(observation.status)) return "";
  const to = redirectHost(observation.location);
  return to && to !== from && serving.includes(to) ? to : "";
}

/**
 * Invariant 11. A 200 on pages.dev says NOTHING about whether client.com
 * resolves, holds a certificate, or is serving this site -- and client.com is
 * the only URL anybody will ever type. Every host the project answers on is
 * proven, or the run fails.
 */
async function verifyPublic(ctx) {
  // Which hosts served THIS repo's body, and which were excused because they
  // redirected at one that was supposed to. The second list is settled only
  // after every host has been probed -- see resolveDeferredRedirects.
  ctx.provenHosts = new Set();
  ctx.deferred = [];

  const primary = await verifyPublicDomain(ctx, ctx.domain);
  if (primary !== 0) return primary;
  const rest = await verifyRemainingDomains(ctx);
  if (rest !== 0) return rest;
  return resolveDeferredRedirects(ctx);
}

/**
 * Invariant 11's exemption, settled (issue #104).
 *
 * A 3xx from one serving host to another is the ordinary shape of a launched
 * site, so it is excused rather than read as a lock. But the excuse used to be
 * granted on the redirect's SHAPE -- "the target is a host this project serves,
 * which is proven separately" -- and never checked against the target actually
 * having been proven. `pages.dev -> www -> apex -> www` satisfies every hop, so
 * a redirect CYCLE passed with exit 0 while no host anywhere served the body.
 * That address is ERR_TOO_MANY_REDIRECTS in a browser, and the run then
 * published it as a proven fact.
 *
 * So an excused host is honoured only when following its chain terminates at a
 * host that ended the run with a body carrying this repo's source-repo meta.
 * A cycle terminates nowhere and fails, which is invariant 2 restated as a
 * post-condition: at least one host really served this site, or nothing is
 * proven.
 */
function resolveDeferredRedirects(ctx) {
  const { logger, deferred, provenHosts } = ctx;
  if (deferred.length === 0) return 0;

  const targetOf = new Map(deferred.map((d) => [d.domain, d.target]));
  for (const { domain, target, final } of deferred) {
    const chain = [domain];
    let host = target;
    let arrived = false;
    for (;;) {
      chain.push(host);
      if (provenHosts.has(host)) {
        arrived = true;
        break;
      }
      // Back to a host already on this chain: a cycle, and no way out of it.
      if (chain.indexOf(host) < chain.length - 1) break;
      if (!targetOf.has(host)) break;
      host = targetOf.get(host);
    }

    if (arrived) {
      logger.info(
        `https://${domain} redirects to https://${target} (HTTP ${final.status}), and following that ` +
          `chain (${chain.join(" -> ")}) ends at a host that served this repo's content. That is a ` +
          `www-style redirect, not a gate.`
      );
      continue;
    }

    logger.error(
      `https://${domain} redirects to https://${target} (HTTP ${final.status}), and following that ` +
        `chain never reaches a host that served this site: ${chain.join(" -> ")}. Every host in it ` +
        `answers with another redirect, so a visitor typing the address gets a redirect loop -- ` +
        `ERR_TOO_MANY_REDIRECTS in a browser -- and not the client's site. This is the ordinary ` +
        `result of an apex page rule and a www redirect rule pointing at each other. A 3xx between ` +
        `two hosts this project serves is only proof when one of them actually serves the site. ` +
        `NOTHING WAS ROLLED BACK, NOTHING WAS DELETED, AND NO DNS RECORD WAS TOUCHED.`
    );
    return 1;
  }
  return 0;
}

async function verifyRemainingDomains(ctx) {
  const { logger, cf, repo, serving } = ctx;
  const rest = serving.filter((d) => d !== ctx.domain);
  if (rest.length === 0) return 0;

  logger.info(`This project also answers on ${rest.join(", ")}. Proving each of them.`);
  for (const domain of rest) {
    const final = await pollToDeadline(
      ctx,
      (r) => r.status === "200" && bodyDeclaresRepo(r.body, repo),
      domain
    );
    if (final.proven) {
      logger.info(`https://${domain} serves this repo's content too.`);
      ctx.provenHosts.add(domain);
      continue;
    }

    const sibling = redirectsToSibling(final, serving, domain);
    if (sibling) {
      logger.info(
        `https://${domain} redirects to https://${sibling} (HTTP ${final.status}), which this project ` +
          `also serves. Held: a redirect is proof only if what it points at proves out, which this ` +
          `run decides once every host has been probed.`
      );
      ctx.deferred.push({ domain, target: sibling, final });
      continue;
    }

    // Proven not-this-site on a host real visitors use. Is it locked, or dead?
    const found = await cf.findAccessApp(domain);
    if (redirectsToAccessLogin(final) || (found.listOk && found.app)) {
      logger.error(
        `PROVEN LOCKED -- https://${domain} is a custom domain on this launched site and it does not ` +
          `serve the site to an anonymous visitor (HTTP ${final.status}` +
          `${final.location ? `, redirecting to ${final.location}` : ""}). This is the hostname the ` +
          `client hands out, so a gate here is the whole audience locked out.`
      );
      return await publicRemoveGateAndReport(ctx, domain);
    }

    logger.error(
      `https://${domain} is a custom domain on this Pages project and it is NOT serving this site ` +
        `(last HTTP ${final.status}). ${
          ctx.declared === domain
            ? `The caller declared it, so this is the URL the client was promised. `
            : `It is attached to the project in Cloudflare, so visitors reach it. `
        }` +
        `https://${ctx.domain} answered correctly, which proves only that the deployment succeeded -- ` +
        `nobody visits a pages.dev address. Usual causes, in order: the DNS record for ${domain} does ` +
        `not point at this Pages project, the certificate has not been issued yet (give it a few ` +
        `minutes and re-run), or the domain is attached to a different project. NOTHING WAS ROLLED ` +
        `BACK, NOTHING WAS DELETED, AND NO DNS RECORD WAS TOUCHED -- the publisher does not attach ` +
        `domains, because the agency often does not hold the client's zone.`
    );
    return 1;
  }
  return 0;
}

async function verifyPublicDomain(ctx, domain) {
  const { logger, cf, projectName, repo, timing, serving } = ctx;

  // Invariant 7: a bare 200 is not proof. Cloudflare placeholder pages, Access
  // error pages and stale unrelated projects all answer 200. Proof that THIS
  // site is live is the body carrying this repo's recognition meta.
  const final = await pollToDeadline(ctx, (r) => r.status === "200" && bodyDeclaresRepo(r.body, repo), domain);
  if (final.proven) {
    logger.info(`Public site is live and serving this repo's content: https://${domain}`);
    ctx.provenHosts.add(domain);
    return 0;
  }

  const sibling = redirectsToSibling(final, serving, domain);
  if (sibling) {
    logger.info(
      `https://${domain} redirects to https://${sibling} (HTTP ${final.status}), which this project ` +
        `also serves. Not a gate -- but held until the target proves out in its own right, because a ` +
        `redirect whose destination never serves anything is a dead address, not a launched site.`
    );
    ctx.deferred.push({ domain, target: sibling, final });
    return 0;
  }

  if (isRedirect(final.status)) {
    if (redirectsToAccessLogin(final)) {
      logger.error(
        `PROVEN LOCKED -- https://${domain} redirects to a Cloudflare Access login ` +
          `(${describeObservation(final)}) even though this site is launched (mode: public). A live ` +
          `client site that answers a visitor with a login page is invisible to their customers.`
      );
      return await publicRemoveGateAndReport(ctx, domain);
    }
    // Not the Access login and not a host this project serves. Issue #102's
    // mirror image: calling this a lock removes an Access app that was never the
    // problem, and calling it fine publishes an address that serves nothing.
    const found = await cf.findAccessApp(domain);
    if (found.listOk && found.app) {
      logger.error(
        `PROVEN LOCKED by configuration -- https://${domain} answered ${describeObservation(final)}, ` +
          `which is neither this site's content nor a host this project serves, and Access app ` +
          `${found.app.id} covers the domain. This site is launched, so that gate has to go.`
      );
      return await publicRemoveGateAndReport(ctx, domain);
    }
    logger.error(
      `https://${domain} answered ${describeObservation(final)}. That is not this site's content, not ` +
        `a Cloudflare Access login, and not a host this Pages project serves, so a visitor typing the ` +
        `address does not arrive at the client's site. No Access app covers the domain either, so ` +
        `this is a redirect configured somewhere else -- a page rule, a bulk redirect, or a DNS ` +
        `record pointing at something that is not this project. NOTHING WAS ROLLED BACK, NOTHING WAS ` +
        `DELETED, AND NO DNS RECORD WAS TOUCHED.` +
        (found.listOk ? "" : ` (The Access configuration could not be read either: ${found.error}.)`)
    );
    return 1;
  }

  if (final.status === "200") {
    // Something answered, but it is not this site. An Access-branded "you do not
    // have permission" page is exactly this: HTTP 200, and a lock.
    const found = await cf.findAccessApp(domain);
    if (found.listOk && found.app) {
      logger.error(
        `PROVEN LOCKED -- https://${domain} answers 200 but the body is not this site's content, and ` +
          `Access app ${found.app.id} covers the domain. That is an Access error page, not the client's ` +
          `site.`
      );
      return await publicRemoveGateAndReport(ctx, domain);
    }
    logger.error(
      `https://${domain} answers HTTP 200, but the response body does not carry ` +
        `<meta name="source-repo" content="${repo}">, so this is NOT this site's content -- it is a ` +
        `Cloudflare placeholder, an error page, or a different project on the same name. A bare 200 ` +
        `never counts as proof that a client's site is live. Nothing was rolled back and nothing was ` +
        `deleted; check ${PAGES_PATH} -> ${projectName}.` +
        (found.listOk ? "" : ` (The Access configuration could not be read either: ${found.error}.)`)
    );
    return 1;
  }

  // ── NOTHING SERVED ─────────────────────────────────────────────────────
  const found = await cf.findAccessApp(domain);
  if (!found.listOk) {
    logger.error(
      `https://${domain} did not answer within ${timing.budget}s (last HTTP ${final.status}), and the ` +
        `Access configuration could not be READ (${found.error}) -- which is not the same as finding ` +
        `no gate. Whether this launched site is reachable is unproven in both directions. Give the ` +
        `Cloudflare token '${ACCESS_PERMISSION}' and re-run, so this check can tell a site that is ` +
        `merely slow to reach the edge from one that is gated. Nothing was rolled back and nothing ` +
        `was deleted.`
    );
    return 1;
  }

  if (found.app) {
    // A gate covering the domain is a proven lock even with no answer from the
    // edge. The API is authoritative about configuration.
    logger.error(
      `PROVEN LOCKED by configuration -- https://${domain} did not answer (last HTTP ${final.status}), ` +
        `and Access app ${found.app.id} covers the domain. This site is launched, so that gate has to go.`
    );
    return await publicRemoveGateAndReport(ctx, domain);
  }

  const deployments = await cf.listDeployments(projectName);
  const latestProduction = (deployments.json?.result ?? []).find((d) => d?.environment === "production");
  const latestOk = (latestProduction?.latest_stage?.status ?? "") === "success";
  if (latestOk) {
    logger.warning(
      `REACHABILITY NOT CONFIRMED -- https://${domain} did not answer within ${timing.budget}s (last ` +
        `HTTP ${final.status}), but no Access app gates it and Cloudflare reports the latest ` +
        `production deployment succeeded. A brand new project answers 522 at the edge for several ` +
        `minutes. Open https://${domain} yourself before telling the client it is live.`
    );
    return 0;
  }

  logger.error(
    `https://${domain} is not serving (last HTTP ${final.status}) and Cloudflare reports the latest ` +
      `production deployment for '${projectName}' as ` +
      `'${latestProduction?.latest_stage?.status ?? "missing"}'. The client's live site is not up. ` +
      `Nothing was rolled back and nothing was deleted; check ${PAGES_PATH} -> ${projectName}.`
  );
  return 1;
}

/**
 * The public branch's ONLY corrective action: remove the Access app, then
 * re-probe and say plainly whether the site is now serving or still locked.
 * Fails the run either way -- the site was locked when it was checked, and an
 * agency needs to know that happened.
 */
async function publicRemoveGateAndReport(ctx, domain = ctx.domain) {
  const { logger, cf, repo } = ctx;

  const found = await cf.findAccessApp(domain);
  if (!found.listOk) {
    // Issue #118. This is the branch a Pages-only token now reaches, and it is
    // reached with POSITIVE EVIDENCE of a lock at the edge. Naming the scope is
    // the whole point: the old run told an agency to wait for propagation and
    // re-run, which did the same thing forever while the client's live site
    // answered every visitor with a login page.
    logger.error(
      `https://${domain} is LOCKED and this run could not read the Access configuration to find the ` +
        `application doing it (${found.error}). The likeliest cause is the Cloudflare token: it needs ` +
        `'${ACCESS_PERMISSION}' to see, and Edit to remove, an Access application. Nothing was ` +
        `removed and nothing was destroyed. Either re-run with a correctly scoped token, or remove it ` +
        `by hand now -- the client's live site is unreachable until you do: ${ZERO_TRUST_PATH}, find ` +
        `the application covering ${domain}, delete it.`
    );
    return 1;
  }
  if (!found.app) {
    // Reaching here now means the token CAN read Access and there genuinely is
    // no application covering the domain, which is why propagation is a fair
    // reading of it. It stopped being the answer given to a token that simply
    // could not see (issue #118).
    logger.error(
      `No Access app covers ${domain}, and this token can read Access, so the lock is not one this ` +
        `publisher can remove. It may be Access propagation still catching up, or a gate applied at a ` +
        `different layer. Re-run in a few minutes; if it persists, check ${ZERO_TRUST_PATH}.`
    );
    return 1;
  }

  const del = await cf.deleteAccessApp(found.app.id);
  if (cf.ok(del)) {
    logger.info(`Removed Access app ${found.app.id} ('${found.app.name}') gating ${domain}.`);
  } else {
    logger.error(
      `Could not remove Access app ${found.app.id} gating ${domain}: ${cf.firstError(del)}. The ` +
        `Cloudflare token most likely lacks 'Access: Apps and Policies: Edit'. Remove it by hand NOW ` +
        `-- the client's live site is locked until you do: ${ZERO_TRUST_PATH}, find the application ` +
        `covering ${domain}, delete it.`
    );
  }

  const after = await reprobe(ctx, (r) => r.status === "200" && bodyDeclaresRepo(r.body, repo), domain);
  if (after.fixed) {
    logger.error(
      `https://${domain} is serving this site's content again (HTTP ${after.status}) now that the ` +
        `gate is gone. The run still FAILS: this launched site was locked when it was checked, and ` +
        `the caller workflow should not have needed a gate removed at all.`
    );
  } else {
    logger.error(
      `STILL LOCKED -- https://${domain} is not serving this site's content (last HTTP ` +
        `${after.status}) after the removal above. The client's live site is unreachable right now. ` +
        `Remove the Access application covering ${domain} by hand: ${ZERO_TRUST_PATH}. Nothing was ` +
        `rolled back: a rollback cannot un-gate a site, because the gate is in Access configuration ` +
        `and not in the deployment.`
    );
  }
  return 1;
}

// ─────────────────────────────────────────────────────────────────────────
export async function runPostDeployVerify({ env, logger, fetchImpl, sleep = realSleep, now = Date.now }) {
  const mode = readExplicit(env, "MODE");
  if (!isValidMode(mode)) {
    // Neither verification path may run on a mode the publisher does not
    // understand. Earlier steps reject this, and so does this one.
    logger.error(
      `Post-deploy verification refused to run: mode '${mode}' is not one of ${MODES.join(", ")}. ` +
        `Neither the gated nor the public proof applies, so nothing was checked and nothing was acted on.`
    );
    return 1;
  }

  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const repo = readExplicit(env, "REPO").trim();
  const createdHere = readExplicit(env, "PROJECT_CREATED_HERE");
  const firstDeploy = createdHere === "true" || readExplicit(env, "FIRST_DEPLOY") === "true";
  const cf = createCloudflare({ accountId, token, fetchImpl });

  // Re-resolve the domain now that the deploy has happened: only now is the
  // project certainly present, and only its real .subdomain is certainly the
  // host the site is served at.
  const resolved = await resolveDomain(cf, projectName, logger);
  const hint = readExplicit(env, "DOMAIN_HINT").trim();
  const domain = resolved.domain || hint;

  // ── the read has to have SUCCEEDED, not merely returned (issue #120) ─────
  //
  // `customDomains` from a failed read is empty because nothing was observed,
  // and both branches read it as fact. Gated: invariant 10's post-deploy
  // backstop -- the one that exists precisely for a domain attached DURING the
  // run -- was empty too, so the proof was collected on pages.dev and the run
  // exited 0 with "This unlaunched site is not readable by the public" while it
  // was readable at client.com. Public: invariant 11 requires every serving host
  // to be proven, and a set this run could not enumerate cannot be proven.
  //
  // Neither is a destructive outcome. The deployment is live and is left exactly
  // as it is.
  if (!resolved.readOk) {
    logger.error(
      `The Cloudflare Pages project '${projectName}' could not be read after the deploy, so this run ` +
        `does not know which hosts it answers on. That is not the same as a project with no custom ` +
        `domains, and the difference decides the whole check: in gated mode an Access app covers only ` +
        `the hosts it names, and in public mode every host the project serves has to be proven. ` +
        `Nothing is proven in either direction. The deployment is live and was left exactly as it is: ` +
        `nothing was rolled back, nothing was deleted, and no DNS record was touched. Re-run; if it ` +
        `persists, check the Cloudflare token and account id.`
    );
    return 1;
  }
  if (!domain) {
    logger.error(
      `Cloudflare reports no .subdomain for Pages project '${projectName}' and no earlier step in this ` +
        `run resolved one either, so there is no host to probe. The publisher will not guess ` +
        `'${projectName}.pages.dev' (ARCHITECTURE.md invariant 12). Nothing was rolled back and ` +
        `nothing was deleted.`
    );
    return 1;
  }

  const declared = readExplicit(env, "CUSTOM_DOMAIN").trim().toLowerCase();
  const customDomains = resolved.customDomains ?? [];

  const ctx = {
    logger,
    cf,
    fetchImpl,
    sleep,
    now,
    domain,
    projectName,
    repo,
    createdHere,
    declared,
    // The gated branch REFUSES these (invariant 10): an Access app covers the
    // hosts it names, so a gate cannot be proven on a domain outside it.
    customDomains,
    // The public branch PROVES them (invariant 11): a launched site answering on
    // client.com is the normal case, and a 200 on pages.dev says nothing about
    // whether the URL the client hands out resolves at all.
    serving: [domain],
    timing: timings(env, firstDeploy),
  };

  if (mode === "gated") {
    logger.info(
      `Post-deploy verification: mode=${mode} domain=${domain} first-deploy=${firstDeploy} ` +
        `budget=${ctx.timing.budget}s`
    );
    return await verifyGated(ctx);
  }

  // Discovery is authoritative and a declaration that contradicts it fails --
  // after the deploy as well as before it, because a domain can be attached or
  // detached while a run is in flight. Nothing here is destructive.
  const reconciled = reconcileCustomDomains({
    declared,
    discovered: customDomains,
    projectExists: resolved.projectExists,
    pagesDomain: domain,
  });
  for (const w of reconciled.warnings) logger.warning(w);
  if (!reconciled.ok) {
    logger.error(
      `${reconciled.error} The deployment is live and was left exactly as it is: nothing was rolled ` +
        `back, nothing was deleted, and no DNS record was touched.`
    );
    return 1;
  }
  ctx.serving = reconciled.serving;

  logger.info(
    `Post-deploy verification: mode=${mode} domain=${domain} serving=${ctx.serving.join(",")} ` +
      `canonical=${reconciled.canonicalHost} first-deploy=${firstDeploy} budget=${ctx.timing.budget}s`
  );
  return await verifyPublic(ctx);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(await runPostDeployVerify({ env: process.env, logger }));
}
