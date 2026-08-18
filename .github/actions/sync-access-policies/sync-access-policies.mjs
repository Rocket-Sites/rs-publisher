#!/usr/bin/env node
// GATED MODE ONLY. Reconcile the managed Cloudflare Access policy on an app
// from the declared inputs (ARCHITECTURE.md invariant 3).
//
// Reconciliation is by REPLACEMENT and the ordering is lockout-safe:
//
//   1. validate every input BEFORE any mutation. A malformed email that only
//      surfaces when Cloudflare rejects the create -- after the old policies
//      were deleted -- locks everyone out of the site.
//   2. create the new policy at a precedence that collides with nothing
//      currently attached.
//   3. only after the create succeeds, delete the pre-existing policies.
//   4. read the policy list back and prove the deletes actually landed.
//   5. refuse to report success on a gate that admits nobody (issue #219). With
//      zero declared grants the reconciliation still runs -- nobody is declared,
//      so nobody keeps an old grant -- and then the run FAILS, before the upload,
//      which is the same verdict post-deploy-verify.mjs reaches on the same
//      state. Those two files used to disagree, and which one an operator met
//      depended on how fast the Cloudflare edge answered.
//
// A failure at any point leaves the previous, working policies in place. At no
// moment during a sync does the app have zero policies. A manual dashboard edit
// is overwritten on the next deploy rather than failing it: an agency that
// learns to ignore a red deploy is worse off than one whose edit was reverted.
//
// Step 4 is invariant 2 applied to the question this action exists to answer
// (issue #139). A failed delete used to be a ::warning:: and an exit 0, so an
// ex-client's grant stayed attached and allowing while the deploy went green;
// nothing downstream could see it, because the post-deploy proof notices only
// the zero-policy case. The end STATE is what "who can see this site" is a
// property of, so the end state is what gets read back.
//
// There is NO default grant anywhere in this file. An empty agency-domain
// produces no email_domain include, full stop. A fallback domain filling in for
// a deliberately empty input silently hands every employee of some company
// access to a client's unlaunched site.

import { createLogger, readExplicit, realSleep } from "../_lib/io.mjs";
import { createCloudflare } from "../_lib/cf.mjs";
import { splitList, isValidEmail, isValidEmailDomain } from "../_lib/validate.mjs";

export const MANAGED_POLICY_NAME = "Rocket Sites managed allow";

export function buildIncludes({ agencyDomain, clientDomain, clientEmails }) {
  const includes = [];
  const seen = new Set();
  const push = (key, value) => {
    const dedupe = `${key}:${value.toLowerCase()}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);
    includes.push(key === "email_domain" ? { email_domain: { domain: value } } : { email: { email: value } });
  };
  if (agencyDomain) push("email_domain", agencyDomain);
  if (clientDomain) push("email_domain", clientDomain);
  for (const email of clientEmails) push("email", email);
  return includes;
}

export function firstFreePrecedence(existing) {
  const used = new Set(existing.map((p) => Number(p.precedence)).filter((n) => Number.isFinite(n)));
  let candidate = 1;
  while (used.has(candidate)) candidate += 1;
  return candidate;
}

export async function runSyncAccessPolicies({ env, logger, fetchImpl, sleep = realSleep }) {
  void sleep;
  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const appId = readExplicit(env, "APP_ID");

  // No fallbacks. readExplicit returns "" for an unset variable and "" for one
  // that was deliberately set empty, and both mean the same thing: no grant.
  const agencyDomainRaw = readExplicit(env, "AGENCY_DOMAIN").trim();
  const clientDomainRaw = readExplicit(env, "CLIENT_DOMAIN").trim();
  const clientEmailsRaw = readExplicit(env, "CLIENT_EMAILS");

  if (!token || !accountId || !appId) {
    logger.error(`sync-access-policies needs CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID and APP_ID.`);
    return 1;
  }

  // ── 1. Validate everything before touching anything ────────────────────
  const clientEmails = splitList(clientEmailsRaw);
  for (const email of clientEmails) {
    if (!isValidEmail(email)) {
      logger.error(
        `Invalid address in client-emails: '${email}'. No policies were changed -- the site's access ` +
          `is exactly what it was before this run. Fix the address and re-run.`
      );
      return 1;
    }
  }
  for (const [name, value] of [
    ["agency-domain", agencyDomainRaw],
    ["client-domain", clientDomainRaw],
  ]) {
    if (value && !isValidEmailDomain(value)) {
      logger.error(
        `Invalid ${name}: '${value}'. It must be a bare email domain such as example.com, with no ` +
          `'@' and no scheme. No policies were changed.`
      );
      return 1;
    }
  }

  const includes = buildIncludes({
    agencyDomain: agencyDomainRaw,
    clientDomain: clientDomainRaw,
    clientEmails,
  });

  const cf = createCloudflare({ accountId, token, fetchImpl });

  // ── 2. Read the whole existing policy list ─────────────────────────────
  const listed = await cf.listAllPolicies(appId);
  if (!listed.listOk) {
    logger.error(
      `Could not read the existing Access policies on app ${appId} (${listed.error}). A partial view ` +
        `is not a view: proceeding would delete policies this run never saw. Nothing was changed.`
    );
    return 1;
  }
  const existing = listed.policies;
  logger.info(
    `Existing policies on ${appId}: ${
      existing.length === 0
        ? "none"
        : existing.map((p) => `${p.id} prec=${p.precedence} ${p.name}`).join(", ")
    }`
  );

  const zeroGrant = includes.length === 0;
  const emptyInputs = [
    ["agency-domain", agencyDomainRaw],
    ["client-domain", clientDomainRaw],
    ["client-emails", clientEmailsRaw.trim()],
  ]
    .filter(([, v]) => !v)
    .map(([name]) => name);
  if (zeroGrant) {
    // The Rocket Sites specific case. A gated deploy that resolves to zero valid
    // grants means the caller dispatched before the repo variables existed, or
    // every address was a typo. The reconciliation still runs -- nobody is
    // declared, so nobody keeps their old access -- and then the RUN FAILS. It
    // is never a fall back to public, and never a log line claiming access is
    // configured.
    logger.warning(
      `This site is GATED TO NOBODY. Access is configured for zero people because ${emptyInputs.join(", ")} ` +
        `${emptyInputs.length === 1 ? "is" : "are"} empty, so the Access app will turn away the client too. ` +
        `The pre-existing grants are still being removed, because nobody is declared and nobody may ` +
        `keep an old one, and then this run FAILS: see the error at the end. This is not "access ` +
        `configured".`
    );
  }

  // ── 3. Create first, at a precedence that collides with nothing ────────
  //
  // Except when there is nothing to grant. A zero-grant sync used to POST
  // `{decision:"allow", include: []}` and handle only the case where Cloudflare
  // REJECTED it -- on the strength of a comment saying it does so "on some API
  // versions". If a version ACCEPTS it, the old code logged "Created policy" and
  // then deleted every pre-existing one, leaving an unlaunched client site's
  // Access app with one ALLOW policy whose include list is empty. What an empty
  // include MEANS is exactly the thing nobody measured, and this file's standard
  // is that the response gating a security decision is measured and recorded
  // (cf.mjs RECORDED_ERRORS does that for five other codes).
  //
  // So the call is not made, and deleting the stale policies below is the whole
  // of the work (issue #139).
  //
  // THE SENTENCE THAT USED TO BE HERE WAS WRONG (issue #219). It read "An Access
  // app with zero policies denies everyone -- which post-deploy-verify.mjs
  // already relies on". post-deploy-verify.mjs does the opposite: it reads that
  // exact state and returns 1, because an app that gates the client out as well
  // proves nothing about the deploy that just ran. Two files disagreed about
  // whether a zero-grant gated deploy may succeed, each pinned green by its own
  // test with nothing binding them, and which one an operator met depended on
  // how fast the Cloudflare edge answered: the sync's position won when the edge
  // proved the redirect inside the budget, the verifier's won when it did not --
  // slowest on a FIRST deploy, which is exactly when zero grants happen.
  //
  // post-deploy-verify's position is the one that holds, per CLAUDE.md hard rule
  // 5: never report success on an unproven state, and never infer restriction.
  // An app with no policies is a gate nobody declared and nobody measured, which
  // is the same unmeasured semantic this branch refuses to rest on one paragraph
  // up. So the reconciliation happens and the RUN FAILS at the end of this file.
  let managedId = null;
  if (zeroGrant) {
    logger.info(
      `No policy is being created: there is nobody to grant. An 'allow' policy carrying an empty ` +
        `include list would rest on what Cloudflare does with one, which nobody here has measured.`
    );
  } else {
    const precedence = firstFreePrecedence(existing);
    // `decision` is the field that decides whether the gate authenticates ANYONE,
    // and it has exactly one correct value here. Cloudflare's `bypass` means no
    // authentication at all: the Access app still exists, the publisher still
    // reports a configured gate, and every unlaunched client site behind it is
    // world-readable. It survived a mutation with all 205 tests green (issue #108)
    // because the suite asserted on `include` and on precedence and never on this.
    // It is now asserted directly, and `bypass` must not appear in this file.
    const payload = { name: MANAGED_POLICY_NAME, decision: "allow", precedence, include: includes };
    logger.info(`Creating the managed allow policy at precedence ${precedence} with ${includes.length} include(s).`);
    const created = await cf.createPolicy(appId, payload);

    if (!cf.ok(created)) {
      logger.error(
        `Failed to create the managed allow policy: ${cf.firstError(created)}. The existing policies ` +
          `were left untouched, so access to this site is unchanged and nobody has been locked out.`
      );
      return 1;
    }
    managedId = created.json?.result?.id ?? null;
    logger.info(`Created policy ${managedId ?? "(id unknown)"} at precedence ${precedence}.`);
  }

  // ── 4. Only now delete the pre-existing policies ───────────────────────
  for (const policy of existing) {
    const del = await cf.deletePolicy(appId, policy.id);
    if (cf.ok(del)) {
      logger.info(`Removed superseded policy ${policy.id} (${policy.name}).`);
    } else {
      logger.warning(
        `Could not remove the superseded policy ${policy.id} (${policy.name}): ${cf.firstError(del)}.`
      );
    }
  }

  // ── 5. Prove the reconciliation actually reconciled (issue #139) ───────
  //
  // Each failed delete used to be a ::warning:: and this function returned 0. No
  // attacker required: an agency removes a departed contact from `client-emails`
  // and redeploys, the create succeeds, the delete of the old managed policy
  // 429s. The old policy is still attached, still `allow`, still naming the
  // ex-client. The deploy is green, the address is published, and nothing
  // downstream re-checks -- the post-deploy proof notices only the ZERO-policy
  // case and cannot see a stale extra one. It was the one place in this file
  // where invariant 2 was not applied, and it was applied to exactly the
  // question the action exists to answer.
  //
  // So the end state is READ BACK. Not the delete results: the STATE, because
  // that is what "who can see this site" is a property of.
  const after = await cf.listAllPolicies(appId);
  if (!after.listOk) {
    logger.error(
      `The Access policies on app ${appId} could not be re-read after the sync (${after.error}), so ` +
        `whether this run left exactly the policy it meant to is unknown. A delete that failed leaves ` +
        `an old grant attached and still allowing, and this is the only check that would see it. ` +
        `Refusing to report a successful sync on an unverified state.`
    );
    return 1;
  }
  // Judged as "did any policy this run set out to delete survive", not as "is
  // the set exactly {managed}". The two differ on a policy somebody attached in
  // the Cloudflare dashboard DURING the run, which this sync never saw and did
  // not fail to delete: the next deploy reconciles it away, and failing a deploy
  // over it would be reporting on something this run did not do.
  const attempted = new Set(existing.map((p) => p.id));
  const survivors = after.policies.filter((p) => attempted.has(p.id));
  if (survivors.length > 0) {
    for (const p of survivors) {
      const who = JSON.stringify(p.include ?? []);
      logger.error(
        `Access policy ${p.id} ('${p.name ?? "unnamed"}') is STILL ATTACHED to app ${appId} after this ` +
          `sync and this run did not create it. It grants ${who}. Every deploy reconciles the policies ` +
          `by replacement, so a survivor is a grant nobody declared -- typically an address removed ` +
          `from client-emails whose delete failed. Remove it in Cloudflare Zero Trust -> Access -> ` +
          `Applications, or re-run this deploy.`
      );
    }
    logger.error(
      `Policy sync FAILED: ${survivors.length} pre-existing polic${survivors.length === 1 ? "y" : "ies"} ` +
        `survived. The site's access is NOT what this deploy declared.`
    );
    return 1;
  }

  // ── 6. A gate that admits nobody is not a gate this run may pass ──────
  //
  // The reconciliation did what it was told and the end state is exactly what
  // was declared, which is nothing. That is not a success (issue #219). The site
  // is unlaunched and nothing has been uploaded -- this step runs before the
  // Pages deploy -- so the failure costs an agency a re-run and no exposure,
  // while the alternative is a green deploy of a site literally nobody can open,
  // followed ten minutes later by post-deploy-verify saying "Fix the policies
  // and re-run" about a state this step called safe.
  if (zeroGrant) {
    logger.error(
      `Access app ${appId} now carries NO POLICIES, so it turns away the client and the agency along ` +
        `with everyone else, and this run cannot show that anybody may review this site. ` +
        `${emptyInputs.join(", ")} ${emptyInputs.length === 1 ? "is" : "are"} empty. Nothing was ` +
        `uploaded: this step runs before the Pages deploy, so the site still serves whatever it served ` +
        `before. Set client-emails, client-domain or agency-domain and re-run. post-deploy-verify ` +
        `refuses this same state for the same reason, and that is deliberate: a gate whose admit list ` +
        `nobody declared is not a proven gate, in either direction (CLAUDE.md hard rule 5).`
    );
    return 1;
  }

  logger.info(`Policy sync complete: app ${appId} carries exactly the managed policy ${managedId}.`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(await runSyncAccessPolicies({ env: process.env, logger }));
}
