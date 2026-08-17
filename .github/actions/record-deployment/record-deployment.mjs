#!/usr/bin/env node
// Record the address this run PROVED as a GitHub Deployment, so it outlives the
// run's log. ARCHITECTURE.md invariant 12, issue #163.
//
// ── Why this exists beside the step name and does not replace it ──────────
//
// The publisher already publishes the proved origin as the name of a step, and
// the console reads it back from GET /actions/runs/{id}/jobs. That works and it
// EXPIRES: step names live in the run's log, and a repository's log-retention
// setting deletes them after 90 days by default. A client site that has not
// deployed for a quarter therefore lost its address and the console went back to
// "Address not known" about a live, healthy site.
//
// `environment_url` on a Deployment is the field GitHub provides for this exact
// purpose and a Deployment is a permanent repository object. So the two
// mechanisms are ranked rather than merged: the Deployment supersedes the step
// name for the canonical address, the step name remains the fallback for a run
// published before this existed or by a caller whose token could not write one,
// and both are read off THE SAME RUN so they cannot describe different deploys.
// The serving SET (invariant 11) is untouched and stays a step name: a
// Deployment carries one environment_url, and that is the canonical host.
//
// ── WHO WRITES IT: the caller's own GITHUB_TOKEN, and this is load-bearing ─
//
// The token comes in as an input from `${{ github.token }}` in the publish job,
// which is the CONSUMER REPOSITORY'S token, scoped to the consumer repository,
// with `deployments: write` from the caller's own `permissions:` block.
//
// Not the Rocket Sites App's installation token, deliberately. The App holds
// `deployments: write` today and is being narrowed to `read` (#67, #84) because
// nothing consumes the write half; making the App the writer here would make
// that narrowing impossible and stall a decision already taken. It would also
// put a Rocket Lab credential inside an agency's deploy, which CLAUDE.md hard
// rule 1 exists to prevent. With the caller writing and the App only reading,
// the permission the console needs is exactly `deployments: read`.
//
// ── Why nothing here can fail a run ──────────────────────────────────────
//
// By the time this runs the site is deployed and PROVEN. ARCHITECTURE.md's
// threat model records that a consumer repo's default workflow-token permissions
// are "the real ceiling ... which we neither control nor can see", so a caller
// whose default is read-only gets a 403 here through no fault of its own. Turning
// that into a red build would report a failure about a client site that is live
// and correct. Every failure is a warning; the address is still published as the
// step name, and the console falls back to it.

import { createLogger, readExplicit } from "../_lib/io.mjs";

/**
 * THE ENVIRONMENT NAME IS THE CONTRACT, and it is duplicated on purpose.
 *
 * `server/src/inventory.ts` declares PUBLISHED_ADDRESS_ENVIRONMENT with the same
 * literal and filters on it. The two ends run on different machines, in
 * different packages, and share no code -- the publisher runs on an agency's
 * runner and the console runs on ours -- so what they share is one string, and
 * both suites assert the other end still carries it. A name that agrees with
 * nothing is a console that silently reads nothing forever, with every test
 * green.
 *
 * NOT `production`. That name is an agency's to use, it collides with GitHub
 * environment protection rules a site repo may have configured, and a filter on
 * it would read somebody else's deployments as ours.
 */
export const DEPLOYMENT_ENVIRONMENT = "rocket-site";

/** What this step is willing to record as an address. */
const HTTPS_ORIGIN = /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/**
 * Hosts that can never be anybody's site (RFC 2606 / RFC 6761).
 *
 * The console refuses these on the way in and so does this, at the writing end,
 * where refusing costs nothing and stops the record existing at all. The reason
 * is not hypothetical: every template ships `https://example.com/` in its
 * `rocket-site.json`, and the fleet console once rendered "Serving at
 * example.com" as a working link for every site that had never been stamped.
 * A wrong step name expired in 90 days. A wrong Deployment would not.
 */
const RESERVED_HOSTS = /(^|\.)(example\.(com|net|org)|test|invalid|localhost|local)$/;

/** An address is only recordable if it is an https origin nobody could have invented. */
export function recordableAddress(raw) {
  const text = String(raw ?? "").trim();
  if (text.length === 0 || text.length > 300) return null;
  if (!HTTPS_ORIGIN.test(text)) return null;
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  const host = url.host.toLowerCase();
  if (!host || RESERVED_HOSTS.test(host)) return null;
  return url.origin;
}

const headers = (token) => ({
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type": "application/json",
  "User-Agent": "rocket-sites-publisher",
});

export async function runRecordDeployment({ env, logger, fetchImpl = fetch }) {
  const token = readExplicit(env, "GITHUB_TOKEN");
  const repo = readExplicit(env, "REPO");
  const runId = Number(readExplicit(env, "RUN_ID"));
  const sha = readExplicit(env, "RUN_SHA");
  const api = readExplicit(env, "GITHUB_API_URL") || "https://api.github.com";

  const address = recordableAddress(readExplicit(env, "SITE_ADDRESS"));
  if (!address) {
    // Silent for the ordinary empty case (the step's own `if:` already covers
    // it), loud for anything else: an origin that reached here malformed means
    // the stamp step produced something the guard should have caught.
    logger.warning(
      `No recordable site address, so no GitHub Deployment was created. This run's address is still ` +
        `published as the name of the 'Site address' step, which is what the fleet console reads when ` +
        `no Deployment exists. Nothing about the deployed site is affected.`
    );
    return 0;
  }
  if (!token || !repo || !Number.isFinite(runId) || runId <= 0 || !sha) {
    logger.warning(
      `The GitHub Deployment could not be recorded: this step was not given a token, repository, run id ` +
        `and commit. The address ${address} is still published as a step name.`
    );
    return 0;
  }

  const post = async (path, body) => {
    const response = await fetchImpl(`${api}/repos/${repo}${path}`, {
      method: "POST",
      headers: headers(token),
      body: JSON.stringify(body),
    });
    return response;
  };

  let created;
  try {
    created = await post("/deployments", {
      ref: sha,
      environment: DEPLOYMENT_ENVIRONMENT,
      description: `Rocket Sites publish of ${address}`,
      // BOTH OF THESE ARE THE API'S DEFAULTS AND BOTH DEFAULTS ARE WRONG HERE.
      // auto_merge defaults true, which makes GitHub attempt to merge the base
      // branch into the ref and answer 202 with no deployment at all. Nothing
      // is being merged: the commit is already published. required_contexts
      // defaults to every status check on the ref, so any other CI in a site
      // repo turns this into a 409.
      auto_merge: false,
      required_contexts: [],
      production_environment: true,
      transient_environment: false,
      // WHAT BINDS THIS RECORD TO A PROVED PUBLISH. The console only trusts an
      // address from a run GitHub itself reports as having called our publisher
      // (`referenced_workflows`, which a site repository cannot assert about
      // itself), so the Deployment has to name that run. Without it, any
      // workflow in the repository could write an environment_url and the
      // console would render it as "Serving at" with a link.
      payload: { run_id: runId },
    });
  } catch (error) {
    logger.warning(
      `The GitHub Deployment could not be recorded (${error}). The address ${address} is still published ` +
        `as a step name, and the site itself is unaffected.`
    );
    return 0;
  }

  if (created.status !== 201) {
    const detail = await readMessage(created);
    logger.warning(
      `This run could not create a GitHub Deployment on ${repo} (HTTP ${created.status}${detail}). The most ` +
        `likely reason is that the caller workflow's GITHUB_TOKEN does not hold 'deployments: write' -- add ` +
        `it to the 'permissions:' block of the job that calls this publisher. The address ${address} is ` +
        `still published as the name of this run's 'Site address' step, so the fleet console can read it ` +
        `until this run's logs expire.`
    );
    return 0;
  }

  const id = await deploymentId(created);
  if (id === null) {
    logger.warning(
      `GitHub accepted the deployment request for ${repo} but returned no deployment id, so no ` +
        `environment_url could be attached. The address ${address} is still published as a step name.`
    );
    return 0;
  }

  let status;
  try {
    status = await post(`/deployments/${id}/statuses`, {
      state: "success",
      environment: DEPLOYMENT_ENVIRONMENT,
      // THE POINT OF THE WHOLE STEP. This is the field that survives log
      // retention, and it carries the origin this run resolved AND proved -- the
      // same value stamped into every published page.
      environment_url: address,
      description: `Serving at ${address}`,
      auto_inactive: true,
    });
  } catch (error) {
    logger.warning(
      `The deployment status carrying ${address} could not be written (${error}). The address is still ` +
        `published as a step name.`
    );
    return 0;
  }

  if (status.status !== 201) {
    const detail = await readMessage(status);
    logger.warning(
      `A GitHub Deployment was created on ${repo} but its status could not be written ` +
        `(HTTP ${status.status}${detail}), so it carries no environment_url. The address ${address} is ` +
        `still published as a step name.`
    );
    return 0;
  }

  logger.info(
    `Recorded ${address} as the environment_url of GitHub Deployment ${id} on ${repo}. Unlike this run's ` +
      `logs, that record does not expire.`
  );
  return 0;
}

/** The id, only from a body that really is a created deployment. */
async function deploymentId(response) {
  let body;
  try {
    body = await response.json();
  } catch {
    return null;
  }
  const id = body?.id;
  return typeof id === "number" && Number.isFinite(id) ? id : null;
}

/** GitHub's own message, when it sent one, for the warning a human reads. */
async function readMessage(response) {
  try {
    const body = await response.json();
    const message = body?.message;
    return typeof message === "string" && message ? `: ${message}` : "";
  } catch {
    return "";
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const logger = createLogger();
  process.exit(await runRecordDeployment({ env: process.env, logger }));
}
