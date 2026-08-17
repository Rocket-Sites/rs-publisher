#!/usr/bin/env node
// Cloudflare credential pre-flight.
//
// Report exactly what arrived, then prove the token actually reaches the
// account -- BEFORE anything has a side effect. A publish that gets far enough
// to upload and then discovers the token cannot configure Access has already
// put an unlaunched client site on the public internet.
//
// The Access-scope check is where the inversion first shows up:
//   gated  -> the token MUST be able to CREATE an Access app. Without it the
//             gate cannot be built, so the site must not publish. Fatal, and
//             proven with a write (see below). Fatal.
//   public -> nothing needs Access except removing a leftover gate. A missing
//             scope only means that removal cannot happen automatically, which
//             the post-deploy reachability check catches. Warning, and a read
//             is enough to decide it.
//
// ── Why gated mode probes with a WRITE (issue #40) ────────────────────────
//
// A `GET /access/apps` succeeds on a token carrying `Access: Apps and Policies |
// Read` and the `POST` then fails with `RECORDED_ERRORS.accessWriteForbidden`.
// That is not a hypothesis: it was hit on CF_TOKEN_WORK during the first live
// verification of this publisher, reproduced with an explicit User-Agent so it
// was not a WAF block. A read probe therefore passes exactly the token this step
// exists to reject, and the run goes on to build the whole site and CREATE THE
// PAGES PROJECT -- burning one of the 100-per-account cap -- before failing at
// the gate, from a step whose message names the wrong thing.
//
// The body is a value in cf.mjs rather than a sentence here (issue #106).
// Spelled out in prose it drifted from what the parser could actually read, and
// the test suite fed the parser a different shape again -- so this step, whose
// entire purpose is saying WHICH credential problem an agency has, reported
// "HTTP 403" with no classification at all.
//
// So gated mode creates a throwaway Access app and deletes it. The side effect
// is deliberate and its cost is bounded: see cf.accessWriteProbe for the domain
// choice, the collision argument, and why no cheaper capability probe exists.

import crypto from "node:crypto";

import { createLogger, readExplicit } from "../_lib/io.mjs";
import { createCloudflare, RECORDED_ERRORS } from "../_lib/cf.mjs";

/**
 * The name and hostname of the throwaway probe application. Prefixed so a
 * leaked one is recognisable in the Cloudflare dashboard as this publisher's
 * litter rather than as somebody's real gate.
 */
export const PROBE_APP_PREFIX = "rocket-sites-preflight-";

export function probeLabel(random = crypto.randomUUID()) {
  return `${PROBE_APP_PREFIX}${String(random).replace(/[^a-z0-9-]/gi, "").slice(0, 24).toLowerCase()}`;
}

export async function runCheckCredentials({ env, logger, fetchImpl, random }) {
  const token = readExplicit(env, "CLOUDFLARE_API_TOKEN");
  const accountId = readExplicit(env, "CLOUDFLARE_ACCOUNT_ID");
  const mode = readExplicit(env, "MODE");

  // The token is masked by Actions, so only its length is printable. The account
  // id is not a secret, and a blank one otherwise surfaces much later as a
  // cryptic "could not route" from the API.
  logger.info(`CLOUDFLARE_API_TOKEN:  present=${token ? "yes" : "NO"}  length=${token.length}`);
  logger.info(
    `CLOUDFLARE_ACCOUNT_ID: present=${accountId ? "yes" : "NO"}  length=${accountId.length}  value='${accountId}'`
  );

  if (!token || !accountId) {
    logger.error(
      `Cloudflare credentials are empty in this run, so nothing was built or published. ` +
        `Three things produce this, and the third is the likeliest for an agency that has just ` +
        `finished onboarding. (1) The agency's GitHub org has no CLOUDFLARE_API_TOKEN / ` +
        `CLOUDFLARE_ACCOUNT_ID Actions secret -- these are set once by hand at onboarding and are ` +
        `deliberately never written by the extension. (2) The caller workflow is in a different ` +
        `GitHub org than this publisher, so 'secrets: inherit' forwarded nothing: map them by name ` +
        `instead, with a 'secrets:' block passing CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID. ` +
        `(3) THE SECRETS ARE SET AT ORG LEVEL AND THIS REPO IS PRIVATE ON GITHUB FREE. On GitHub ` +
        `Free, organization Actions secrets are available to PUBLIC repositories only; sharing them ` +
        `with private repos needs Team or Enterprise. Client site repos are normally private, so ` +
        `the secrets exist, the org settings page lists them, and every run still arrives with an ` +
        `empty token and no warning from GitHub. Check the org's plan at ` +
        `https://github.com/organizations/<org>/settings/billing. Fix: set both secrets on THIS ` +
        `repository (Settings -> Secrets and variables -> Actions), which works on every plan, or ` +
        `upgrade the org to Team and keep them at org level.`
    );
    return 1;
  }

  const cf = createCloudflare({ accountId, token, fetchImpl });
  const verify = await cf.verifyToken();
  logger.info(`token verify -> ${verify.status} (${verify.scope}-scoped)`);

  if (verify.status !== 200) {
    logger.error(
      `The Cloudflare API token is not live (HTTP ${verify.status}): it did not verify as an ` +
        `account-owned token on ${accountId}, and it did not verify as a user token either. It is ` +
        `expired, revoked, or mistyped. Re-issue it with 'Cloudflare Pages: Edit' and ` +
        `'Access: Apps and Policies: Edit'.`
    );
    return 1;
  }

  // ── the account binding, which the verify above does NOT establish ──────
  //
  // Issue #107. `/user/tokens/verify` returns 200 for any live user token
  // whatever account it belongs to -- measured: CF_TOKEN_PERSONAL is 200 there
  // and 403 on the work account. So the old message's promise to catch "it
  // belongs to a different account than CLOUDFLARE_ACCOUNT_ID" was carried by a
  // check answering a different question, and a wrong-account token passed this
  // step with a warning at most. The run then built the whole site, created
  // nothing, and died at wrangler -- after the step whose entire purpose was to
  // stop that happening. In gated mode it failed later still, at the Access
  // write probe, with a message insisting the cause was a token scope.
  //
  // The account id is the input most likely to be wrong. The token is pasted
  // from a dashboard that shows it once; the account id is a 32-hex string a
  // person transcribes or picks out of a list.
  const bound = await cf.bindsToAccount();
  logger.info(`pages/projects (account binding) -> ${bound.status}`);
  if (bound.status !== 200) {
    const code = cf.firstErrorCode(bound);
    logger.error(
      `This Cloudflare token is live, but it cannot list Pages projects on account ${accountId} ` +
        `(HTTP ${bound.status}: ${cf.firstError(bound)}${code ? `, code ${code}` : ""}). Every deploy ` +
        `needs that, in both modes, so this run stops here: NOTHING WAS BUILT, NOTHING WAS UPLOADED, ` +
        `AND NO PAGES PROJECT WAS CREATED. Two causes, and the first is the likelier: (1) ` +
        `CLOUDFLARE_ACCOUNT_ID names a DIFFERENT account than the one this token is scoped to -- the ` +
        `token verifies fine on its own account, which is why nothing caught this earlier; check the ` +
        `id '${accountId}' against Cloudflare dashboard -> the account -> Account ID. (2) The token ` +
        `does not carry 'Cloudflare Pages: Edit', or its Account Resources do not include this ` +
        `account. Fix whichever it is and re-run; do not widen an Access permission over this ` +
        `message, because Access is not what failed.`
    );
    return 1;
  }

  // ── gated: prove the WRITE, because a GET lies (issue #40) ─────────────
  if (mode === "gated") {
    const label = probeLabel(random ?? crypto.randomUUID());
    logger.info(`Probing Access with a create-then-delete on ${label}.example.com (a GET would pass a read-only token).`);
    const result = await cf.accessWriteProbe(label);

    if (!result.ok) {
      // The diagnosis follows the CODE (issue #107). This message used to insist
      // the cause was Read-instead-of-Edit whatever came back, so an agency
      // whose real problem was elsewhere went and widened a permission that was
      // already correct. The account binding is proven above, so what is left
      // here really is about Access -- but which part of Access is a question
      // the response answers, and 1010 is the only code that says Read vs Edit.
      const readNotEdit =
        result.code === RECORDED_ERRORS.accessWriteForbidden.code ||
        /auth\.forbidden/i.test(result.error ?? "");
      logger.error(
        `This site is deploying in gated mode, but the Cloudflare token CANNOT CREATE a Cloudflare ` +
          `Access application on account ${accountId} (${result.error}${result.code ? `, code ${result.code}` : ""}). ` +
          (readNotEdit
            ? `That code is Cloudflare's Read-instead-of-Edit refusal: the token is scoped 'Access: ` +
              `Apps and Policies: Read' instead of 'Access: Apps and Policies: EDIT'. Reading the ` +
              `application list succeeds with Read and creating one does not, which is why this step ` +
              `no longer accepts a GET as an answer. Fix: edit the token in the Cloudflare dashboard, ` +
              `set 'Access: Apps and Policies' to 'Edit', and re-run. See docs/onboarding.md step 3b. `
            : `This run has already proven the token reaches account ${accountId} with Pages ` +
              `permission, so the account id is not the problem and neither is the token being dead. ` +
              `Read that code and message before changing anything: 'Access: Apps and Policies' ` +
              `missing entirely, an Account Resources restriction, or a Zero Trust plan that does ` +
              `not include Access are the usual answers, and they need different fixes. `) +
          `The gate cannot be built, so the site must not publish: an unlaunched client site would go ` +
          `up with nothing in front of it. NOTHING WAS BUILT, NOTHING WAS UPLOADED, AND NO PAGES ` +
          `PROJECT WAS CREATED.`
      );
      return 1;
    }

    if (!result.cleaned) {
      // Loud, but never fatal. A leaked probe app gates a hostname under
      // example.com that no visitor of any client site ever resolves, so it is
      // litter rather than an exposure -- and failing the run over litter would
      // block a launch for a problem that harms nobody.
      logger.warning(
        `The Access write probe succeeded but its throwaway application could NOT be deleted ` +
          `(${result.cleanupError ?? "unknown error"}). Remove it by hand: Cloudflare dashboard -> ` +
          `Zero Trust -> Access -> Applications -> application id ${result.id} ('${label}'). It ` +
          `covers ${label}.example.com, which is a reserved documentation domain, so it gates ` +
          `nothing real -- this run continues.`
      );
    } else {
      logger.info(`Access write probe passed and left nothing behind (app ${result.id} created and deleted).`);
    }
    return 0;
  }

  // ── public: a read is all this branch could ever need ─────────────────
  //
  // Nothing in a public deploy creates an Access app, so a write probe here
  // would be a side effect on every launch for a capability the run never uses.
  //
  // But it has to be a CAPABILITY probe, not a list (issue #118). The old check
  // was `GET /access/apps?per_page=1`, and a token with no Access permission
  // answers that 200 with an empty collection, because Cloudflare filters the
  // collection by permission rather than refusing the request. So the pre-flight
  // whose job is naming a credential problem passed exactly the token that
  // cannot see -- and cannot remove -- a gate, and the run went on to report
  // "No Access app gates this domain, nothing to remove" over a live client site
  // that was locked. cf.accessReadCapability asks a question with a different
  // answer for the two cases.
  const access = await cf.accessReadCapability();
  logger.info(`access read capability -> ${access.capable ? "yes" : "NO"}`);
  if (!access.capable) {
    logger.warning(
      `The Cloudflare token cannot read Cloudflare Access (${access.error}). That is fine for a public ` +
        `site, and it is NOT an account problem -- the binding to ${accountId} was proven above -- so ` +
        `it means this token simply has no 'Access: Apps and Policies' permission. The consequence is ` +
        `narrow but worth knowing: a leftover Access gate on this domain cannot be found or removed ` +
        `automatically, and this run cannot tell you whether there is one. If the site is still gated ` +
        `after this run, the post-deploy check will say so and name the application to remove by hand.`
    );
  }

  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(await runCheckCredentials({ env: process.env, logger }));
}
