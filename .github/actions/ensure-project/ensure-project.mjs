#!/usr/bin/env node
// Ensure the Cloudflare Pages project exists and is a DIRECT-UPLOAD project,
// and record whether THIS run brought it into existence.
//
// `created-here` is the single most consequential output in the publisher. The
// gated post-deploy check may delete the project when it proves an unlaunched
// client site is being served publicly, and that is only defensible for a
// project this run created -- deleting an agency's pre-existing site over a
// check failure is not a recovery, it is the outage. So the flag is RECORDED by
// the step that actually knows, and is never inferred downstream from any other
// signal. A concurrent run's "name already exists" counts as existing, not ours.

import { createLogger, createOutputs, readExplicit, realSleep } from "../_lib/io.mjs";
import { createCloudflare, PAGES_PROJECT_LIMIT } from "../_lib/cf.mjs";

/**
 * The one create failure this action has an explanation for.
 *
 * Cloudflare's generic internal error. "Usually a transient API blip" is a claim
 * about THIS code and nothing else, so it is only said when this is the code
 * that came back (issue #109).
 */
const TRANSIENT_CREATE_ERROR = "8000000";

/**
 * THE ACCOUNT IS FULL: Cloudflare will not create the 101st Pages project.
 *
 * WHAT IS MEASURED. Cloudflare caps an account at 100 Pages projects, on every
 * plan (PAGES_PROJECT_LIMIT, and ARCHITECTURE.md "Scale ceiling"). A create
 * against a full account has been hit for real on the sibling store accounts
 * and written up in their runbook, where `wrangler pages project create`
 * answered `8000007: Exceeded the maximum`. That refusal happened, and its
 * WORDING is what was read off it.
 *
 * WHAT IS INFERRED, and why this branch does not rest on the number. Nobody has
 * filled an account and watched THIS call -- a direct
 * `POST /accounts/{id}/pages/projects` from these actions -- so `8000007`
 * arriving here is carried across from a different client on a different
 * account. It is not unambiguous even inside this repository: the test harness
 * has answered a GET of a MISSING project with `8000007` since it was written
 * (tests/publisher/stub-cf.mjs, an invented fixture, now labelled as one). A
 * number nobody has observed on this endpoint, which already appears here
 * meaning something else, is not allowed to decide a diagnosis. That is #109's
 * mistake with a different code in it.
 *
 * So the decision is the WORDING, which is the half that was read off a real
 * refusal, and no error code is required or consulted. A refusal this pattern
 * does not recognise is retried and falls through to the unrecognised message
 * below -- which NAMES the cap as one of the things to check, so a quota
 * refusal worded some other way still leaves an operator pointed at the account
 * rather than at their token. If you ever fill an account and watch this
 * endpoint, record the body and the date here.
 *
 * A 429 is excluded by status rather than by wording: a rate limit is the one
 * nearby refusal whose text can also be about exceeding a maximum, it is
 * genuinely transient, and it is exactly the case that should still be retried.
 */
const ACCOUNT_FULL_REFUSAL =
  /exceed(?:ed|s)?\b[^.]{0,40}\bmaximum\b|maximum number of[^.]{0,40}projects?\b|too many projects|project (?:count )?limit\b/i;

function refusalIsAccountFull(status, message, body) {
  if (status === 429) return false;
  return ACCOUNT_FULL_REFUSAL.test(`${message ?? ""} ${body ?? ""}`);
}

export async function runEnsureProject({ env, logger, outputs, fetchImpl, sleep = realSleep }) {
  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const projectName = readExplicit(env, "PROJECT_NAME");
  const cf = createCloudflare({ accountId, token, fetchImpl });

  // Unknown ownership stays false. A missed delete leaves a job that failed
  // loudly; a wrong one destroys a client's live site.
  let createdHere = false;
  const finish = (code) => {
    outputs.set("created", String(createdHere));
    return code;
  };

  const resp = await cf.getProject(projectName);

  if (resp.status === 200) {
    const sourceType = resp.json?.result?.source?.type ?? "";
    if (sourceType) {
      logger.error(
        `Cloudflare Pages project '${projectName}' is connected to Git (${sourceType}) in the ` +
          `Cloudflare dashboard. Rocket Sites publishes by DIRECT UPLOAD from GitHub Actions and ` +
          `cannot deploy to a Git-connected project. Fix: Cloudflare dashboard -> Workers & Pages -> ` +
          `${projectName} -> Settings -> Delete project, then re-run this deploy and the publisher ` +
          `recreates it correctly. Do not use 'Connect to Git' for a Rocket Sites project.`
      );
      return finish(1);
    }
    logger.info(`Pages project '${projectName}' exists (direct-upload) -- OK.`);
    return finish(0);
  }

  if (resp.status === 404) {
    logger.info(`Creating direct-upload Pages project '${projectName}'...`);
    let exists = false;
    let accountFull = false;
    let lastError = "";
    let lastCode = "";
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const cr = await cf.createProject(projectName);
      // `cf.ok` and nothing weaker (issue #139). This was
      // `cr.status === 200 && cr.json?.success !== false`, and `cr.json` is null
      // for ANY unparseable body while `undefined !== false` is true -- so an
      // HTTP 200 carrying a Cloudflare edge interstitial or a WAF block page set
      // created-here TRUE, which is the sole permission this publisher has to
      // DELETE a Pages project in the gated rollback path. Every other call site
      // in the publisher already used cf.ok(), which requires success === true.
      if (cf.ok(cr)) {
        exists = true;
        createdHere = true;
        logger.info(`Created '${projectName}'.`);
        break;
      }
      // ── "this project already exists, and it is NOT ours" ──────────────
      //
      // This branch sets `created-here: false`, which is the sole permission the
      // publisher has to DELETE a client's Pages project in the gated rollback
      // path. Getting it wrong in either direction is expensive, so what is
      // known and what is not is written down here rather than implied.
      //
      // MEASURED, and NOT what this used to say (issue #105). Cloudflare error
      // `8000009` was matched here as a duplicate-name signal, inherited
      // verbatim from glassdocs' deploy-pages.yml with no verification note in
      // either repo. Live:
      //
      //   GET /accounts/{id}/pages/projects/{name}/deployments/0000...
      //   HTTP 404 {"code":8000009,
      //             "message":"The deployment ID you have specified does not exist."}
      //
      // It means "no such deployment". A 404 from a deployment lookup reaching
      // this classifier would have marked a project as pre-existing when it is
      // not, inverting the delete permission. The number is gone from the
      // branch. Do not re-add it.
      //
      // UNVERIFIED, and deliberately left as a message match: nobody has
      // measured what Cloudflare returns for a duplicate PAGES PROJECT name, so
      // there is no code to branch on. Inventing one would be the same mistake
      // one step further along. Anything this does not recognise is retried and
      // then fails the run with created-here false, which is the safe direction:
      // a missed delete leaves a job that failed loudly, a wrong one destroys a
      // client's live site. If you measure the real response -- attempt a create
      // of an existing project -- record the body and the date here and match on
      // its code.
      //
      // STILL UNMEASURED, and named precisely so the next person can close it
      // (issue #139): a duplicate-name create that answers `200 {success:true}`
      // describing the EXISTING project would satisfy cf.ok above and set
      // created-here TRUE on an agency's pre-existing site, handing the gated
      // rollback path permission to delete it. The classifier cannot tell that
      // response from a real create, and inventing a discriminator is the
      // mistake this comment block already records once. What limits it today is
      // that this branch is only reached after a 404 read of the same project a
      // moment earlier, so the window is a genuine race. Measuring it needs a
      // live account: attempt a create of an existing project, record the body
      // and the date above, and branch on its code.
      const body = cr.text ?? "";
      if (/already exists|not unique/i.test(body)) {
        // A concurrent run created it first. It exists, but it is NOT ours:
        // deleting it later would destroy that run's project.
        exists = true;
        logger.info(`Project '${projectName}' already exists -- continuing. Not created by this run.`);
        break;
      }
      lastError = cf.firstError(cr);
      lastCode = cf.firstErrorCode(cr);
      // A full account is PERMANENT, so it is not retried. Three attempts five
      // seconds apart against a full account spends fifteen seconds proving the
      // account is still full, under a log line promising a retry that cannot
      // work -- the same objection #109 raised to "usually a transient API blip"
      // being printed for a code nobody got.
      if (refusalIsAccountFull(cr.status, lastError, body)) {
        accountFull = true;
        break;
      }
      // Nothing is retried after the last attempt, and the promise of one is not
      // printed after it either: "Retrying in 5s..." on attempt 3 of 3 is a
      // sentence about something that does not happen.
      const retrying = attempt < 3;
      logger.warning(
        `Create attempt ${attempt}/3 failed (HTTP ${cr.status}): ${lastError}.` + (retrying ? " Retrying in 5s..." : "")
      );
      if (retrying) await sleep(5000);
    }
    if (!exists) {
      // -- the account is full, and that is a different sentence entirely ----
      //
      // Every remedy the unrecognised message below offers is WRONG for this one
      // (issue #255): the token's scope is fine, the account id is fine, and no
      // project of this name exists. The account has nowhere to put a 101st
      // site. Naming the limit, naming the account, and saying that a retry
      // cannot help is the whole deliverable here.
      if (accountFull) {
        logger.error(
          `Cloudflare refused to create the Pages project '${projectName}' because ACCOUNT ${accountId} IS FULL ` +
            `(${lastError}${lastCode ? `, code ${lastCode}` : ""}). Cloudflare allows ${PAGES_PROJECT_LIMIT} Pages ` +
            `projects per account, on every plan, and Rocket Sites uses one project per client site. This is a limit ` +
            `on the ACCOUNT and says nothing about the token, this repository or this site: the token's permissions ` +
            `are not the problem, CLOUDFLARE_ACCOUNT_ID is not the problem, and no project of this name is in the ` +
            `way. Retrying cannot free a slot, so this run did not retry. Two remedies, both on the Cloudflare side: ` +
            `free a slot by deleting a Pages project nobody is using (Cloudflare dashboard -> Workers & Pages, or ` +
            `'wrangler pages project list' to see them with their last deployment), or point this repository's ` +
            `CLOUDFLARE_ACCOUNT_ID at another Cloudflare account, which is a repository variable and needs no code ` +
            `change. Nothing was created and nothing was uploaded.`
        );
        return finish(1);
      }
      // The explanation is only offered for the error it explains (issue #109).
      // This used to assert `Cloudflare error 8000000 is usually a transient API
      // blip` whatever came back, next to the real error interpolated
      // separately: a confident diagnosis of a code the operator did not get.
      // And "usually transient" is an INSTRUCTION TO RETRY -- if the real
      // failure is a permission problem or a name collision, retrying is the one
      // thing that cannot work. An unrecognised error honestly labelled is more
      // useful than a recognised one guessed at (the same shape as #105, #107).
      logger.error(
        `Could not create Cloudflare Pages project '${projectName}' after 3 attempts (last: ${lastError}` +
          `${lastCode ? `, code ${lastCode}` : ""}). ` +
          (lastCode === TRANSIENT_CREATE_ERROR
            ? `Cloudflare error ${TRANSIENT_CREATE_ERROR} is usually a transient API blip -- re-run the deploy. If it ` +
              `persists, check the token carries 'Cloudflare Pages: Edit' and that its account matches ` +
              `CLOUDFLARE_ACCOUNT_ID.`
            : `That is not an error this action recognises, so it has no diagnosis to offer beyond the ` +
              `one Cloudflare gave. Do not assume a retry fixes it: check that the token carries ` +
              `'Cloudflare Pages: Edit', that its account matches CLOUDFLARE_ACCOUNT_ID, that no ` +
              `project of this name already exists on the account, and that account ${accountId} is not at ` +
              `Cloudflare's limit of ${PAGES_PROJECT_LIMIT} Pages projects -- a full account is recognised ` +
              `here by the WORDING of the refusal, this refusal did not carry it, and the count is worth ` +
              `taking anyway ('wrangler pages project list'). Nothing was created and nothing was uploaded.`)
      );
      return finish(1);
    }
    return finish(0);
  }

  // ── a credential refusal. NOT a Git-connected project. ─────────────────
  //
  // Issue #107. Everything that was neither 200 nor 404 used to land in the
  // warning below, which told the agency the project was probably Git-connected
  // and to DELETE IT in the Cloudflare dashboard -- the most destructive
  // suggestion this publisher makes, offered on the strength of a status code
  // that does not support it -- and then exited 0. Live-confirmed that a scope
  // or account failure here is 403 with code 10000 "Authentication error", so
  // that is precisely the response that landed there.
  //
  // Git-connectedness is decided by `source` on a readable project, above, and
  // by nothing else. A 403 says only that we were not allowed to look.
  if (resp.status === 401 || resp.status === 403) {
    logger.error(
      `Cloudflare refused to describe the Pages project '${projectName}' on account ${accountId} ` +
        `(HTTP ${resp.status}: ${cf.firstError(resp)}). That is a CREDENTIAL problem and nothing ` +
        `else: either CLOUDFLARE_ACCOUNT_ID names a different account than the token is scoped to, ` +
        `or the token does not carry 'Cloudflare Pages: Edit'. Nothing about this response says ` +
        `anything about how the project is configured, so DO NOT DELETE ANYTHING in the Cloudflare ` +
        `dashboard over it. Nothing was created and nothing was uploaded; fix the credential and ` +
        `re-run.`
    );
    return finish(1);
  }

  logger.warning(
    `Could not verify the Pages project '${projectName}' (HTTP ${resp.status}: ${cf.firstError(resp)}); ` +
      `continuing, because a transient Cloudflare failure must not fail a deploy on its own. If the ` +
      `deploy itself fails, read ITS message: this step established nothing at all about the ` +
      `project, and in particular nothing about whether it is connected to Git.`
  );
  return finish(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  const outputs = createOutputs(process.env);
  process.exit(await runEnsureProject({ env: process.env, logger, outputs }));
}
