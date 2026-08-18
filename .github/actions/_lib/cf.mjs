// Cloudflare API client and the unauthenticated edge probe.
//
// Every network call in the publisher goes through here and takes its `fetch`
// by injection, so the test suite can stand in a stub that returns scripted
// responses and records every call it received in order. Several of the safety
// properties in ARCHITECTURE.md are statements about calls that must NOT be
// made (never roll back in public mode, never delete a project this run did not
// create), and those can only be asserted against a recorded call log.

import { declaredSourceRepo } from "./html.mjs";

export const CF_API = "https://api.cloudflare.com/client/v4";

/**
 * Every outbound request from the publisher identifies itself.
 *
 * This is not politeness. A default runtime User-Agent (undici's, or none at
 * all) is rejected outright by common Cloudflare WAF managed rules and by
 * hand-rolled bot rules an agency may already have on their zone. The rejection
 * arrives as a 403 with a Cloudflare error page, which reads exactly like a
 * token-scope problem -- observed against a live account. Worse, on the
 * unauthenticated edge probe below a WAF block is indistinguishable from a
 * gate, so a publisher with no UA can report "gate confirmed" over a site that
 * is wide open to every browser on earth.
 *
 * Major version only: the string is a stable identifier for a WAF allowlist, so
 * it must not churn on every patch release.
 *
 * THE URL NAMES AN ORG THIS REPOSITORY LEFT, AND IT STAYS (#239). The authoring
 * repo was transferred to another org on 2026-08-17 and this string was not
 * updated with it. That is the decision, not an oversight, and the asymmetry is
 * the whole of the argument:
 *
 *   Correcting it buys nothing anyone can observe. The repository is PRIVATE at
 *   either address, so an agency reading this out of their Cloudflare logs gets
 *   a 404 before and after, and GitHub redirects a transferred path anyway. The
 *   address that would actually help them is the public mirror, which is a
 *   bigger edit to the same frozen string and has itself moved twice.
 *
 *   Churning it can cost a false "gate confirmed". An allowlist written against
 *   the whole string stops matching, and the paragraph above is the failure
 *   mode: a WAF block arrives as a 403 that reads like a token-scope problem,
 *   and on the unauthenticated edge probe it is indistinguishable from a gate.
 *   That is this file reporting a restricted site over one that is wide open.
 *
 * So the stability of the string outranks the accuracy of the URL inside it. If
 * it is ever rebuilt, rebuild it deliberately, as its own release, naming the
 * public mirror rather than a repository no recipient can open.
 */
export const USER_AGENT = "rocket-sites-publisher/1 (+https://github.com/TheRocketLab/rocket-sites)";

/**
 * The `per_page` values Cloudflare's Access API accepts. It is NOT a range.
 *
 * Measured against the live API (issue #108):
 *
 *   1, 5, 10, 20, 25, 50, 100, 1000  -> 200
 *   2, 3, 9, 24, 26, 51              -> HTTP 400
 *                                       {"code":12091,
 *                                        "message":"access.api.error.invalid_url_parameter_value"}
 *
 * An innocuous-looking tuning edit -- 50 to 25 is fine, 50 to 26 is not -- turns
 * every Access list into a hard 400. `findAccessApp` reports that as
 * `listOk: false`, which is "we could not look": in gated mode it fails the
 * publish, and in PUBLIC mode it silently skips gate removal and leaves an
 * Access app in front of a site that is supposed to be world-readable. Two of
 * the three call sites were pinned by nothing at all.
 */
export const ACCESS_PER_PAGE = Object.freeze([1, 5, 10, 20, 25, 50, 100, 1000]);

/**
 * Cloudflare error bodies this publisher has actually SEEN, as data.
 *
 * These used to live in prose, three files apart, and the test suite fed the
 * parser a differently-shaped invention of its own (issue #106). Fed the body as
 * the comments recorded it, the client returned `firstError: "HTTP 403"` and an
 * EMPTY code -- on the pre-flight whose entire job is telling an agency which of
 * several credential problems they have. The fixture reshaped it into a v4
 * envelope nobody has observed, so the assertion passed and the gap between the
 * recorded body and the parser stayed invisible.
 *
 * So the record is a value now, every entry carries where it came from, and a
 * test asserts the client can read a code out of every one of them. A body
 * nobody can parse is not "an error we handle".
 *
 * Cloudflare does NOT speak one error shape. The v4 envelope
 * (`{success, errors:[{code, message}]}`) is the common one; the Access edge
 * answers auth failures with a FLAT `{code, error}`, and the Pages API uses a
 * flat `{code, message}` in places. The client reads all three.
 */
export const RECORDED_ERRORS = Object.freeze({
  accessWriteForbidden: Object.freeze({
    status: 403,
    // Measured on CF_TOKEN_WORK during the first live verification of this
    // publisher (issue #40), reproduced with an explicit User-Agent so it was
    // not a WAF block, and written up in docs/onboarding.md step 3b. A token
    // scoped `Access: Apps and Policies | Read` answers GET /access/apps 200 and
    // 403s the POST with this. NOTE THE SHAPE: no `errors` array, no `success`.
    body: Object.freeze({ code: 1010, error: "auth.forbidden" }),
    code: "1010",
    message: "auth.forbidden",
    means: "the token has Access: Read, not Edit",
  }),
  accountForbidden: Object.freeze({
    status: 403,
    // Live-measured account-permission refusal (issue #106). Glassdocs measured
    // the same condition on two tokens across two accounts and recorded the same
    // code, from `GET /accounts/{id}/access/apps/{nonexistent}/policies`:
    // without the permission 403 `10000`, with it 404 `11021`. Two repos, one
    // number, finally agreeing.
    body: Object.freeze({ success: false, errors: [Object.freeze({ code: 10000, message: "Authentication error" })] }),
    code: "10000",
    message: "Authentication error",
    means: "this token cannot touch this account, or lacks the permission for this endpoint",
  }),
  accessPermissionPresent: Object.freeze({
    status: 404,
    // Measured in Glassdocs (server/src/cloudflare.ts): the token HOLDS the
    // Access permission and the application simply does not exist. Recorded here
    // because it is the only thing that distinguishes "may not" from "not there"
    // on a read-only probe.
    body: Object.freeze({
      success: false,
      errors: [Object.freeze({ code: 11021, message: "access.api.error.unknown_application" })],
    }),
    code: "11021",
    message: "access.api.error.unknown_application",
    means: "the token MAY manage Access apps; that particular app does not exist",
  }),
  deploymentIdNotFound: Object.freeze({
    status: 404,
    // Measured live (issue #105). Recorded because this code was being read as
    // "the Pages project already exists", which gated a project deletion.
    body: Object.freeze({ code: 8000009, message: "The deployment ID you have specified does not exist." }),
    code: "8000009",
    message: "The deployment ID you have specified does not exist.",
    means: "no such deployment. NOT a duplicate project name",
  }),
  accessPerPageInvalid: Object.freeze({
    status: 400,
    // Measured live (issue #108) by asking for a per_page value outside the
    // accepted set -- see ACCESS_PER_PAGE.
    body: Object.freeze({ code: 12091, message: "access.api.error.invalid_url_parameter_value" }),
    code: "12091",
    message: "access.api.error.invalid_url_parameter_value",
    means: "per_page (or another URL parameter) is not one of the values Access accepts",
  }),
});

/**
 * The error out of a body Cloudflare did not send as a v4 envelope.
 * Returns null when there is nothing error-shaped to read.
 */
function flatError(json) {
  if (!json || typeof json !== "object" || json.success === true) return null;
  const message = typeof json.error === "string" ? json.error : typeof json.message === "string" ? json.message : null;
  if (json.code === undefined && message === null) return null;
  return { code: json.code ?? "", message: message ?? "" };
}

/**
 * The application id the Access read-capability probe asks about.
 *
 * A valid v4 UUID that cannot exist: it is the reserved all-zero form with the
 * version and variant nibbles set, so Cloudflare parses it and then reports it
 * as unknown. Fixed rather than random, because the answer is a property of the
 * TOKEN and a random id would make the probe look like traffic.
 */
export const ACCESS_CAPABILITY_PROBE_APP = "00000000-0000-4000-8000-000000000000";

export function createCloudflare({ accountId, token, fetchImpl = globalThis.fetch }) {
  const base = `${CF_API}/accounts/${accountId}`;
  // Whether this token may READ Cloudflare Access, established once. The answer
  // is a property of the credential and cannot change inside a run.
  let accessReadable = null;

  async function api(method, path, body) {
    const init = {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "User-Agent": USER_AGENT,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);

    let res;
    try {
      res = await fetchImpl(`${base}${path}`, init);
    } catch (err) {
      return { status: 0, json: null, text: "", networkError: String(err && err.message ? err.message : err) };
    }
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* a non-JSON body is a legitimate outcome (an HTML error page from the edge) */
    }
    return { status: res.status, json, text };
  }

  const ok = (r) => r.json?.success === true;
  // Reads the v4 envelope first, then the flat shapes Cloudflare also sends
  // (see RECORDED_ERRORS). Falling through to "HTTP 403" with no code is the
  // last resort, not the answer to a body we have on record: an operator whose
  // classification is chosen by a fallback rather than by their actual error is
  // how somebody ends up changing a permission that was already correct.
  const firstError = (r) =>
    r.json?.errors?.[0]?.message ??
    flatError(r.json)?.message ??
    (r.networkError ? `network error: ${r.networkError}` : `HTTP ${r.status}`);
  const firstErrorCode = (r) => String(r.json?.errors?.[0]?.code ?? flatError(r.json)?.code ?? "");

  return {
    api,
    ok,
    firstError,
    firstErrorCode,

    // ---- token / account -------------------------------------------------

    /**
     * Verify the token, whichever KIND of token it is.
     *
     * `/accounts/{id}/tokens/verify` only answers for an ACCOUNT-OWNED token.
     * A user API token -- what the Cloudflare dashboard gives you by default,
     * and what almost every agency will paste -- 401s there and verifies at
     * `/user/tokens/verify` instead. Probing only the account form rejected a
     * perfectly good token during the first real end-to-end deploy, with a
     * message telling the user to re-issue a token that was already correct.
     *
     * Try the account form first (it is the more specific claim), then fall
     * back to the user form. Either 200 means the credential is LIVE, and that
     * is all it means.
     *
     * IT DOES NOT ESTABLISH THE ACCOUNT BINDING (issue #107). Measured:
     * `/user/tokens/verify` returns 200 for any live user token regardless of
     * account -- CF_TOKEN_PERSONAL answers 200 there and 403 on the work
     * account. A caller that needs to know the token reaches THIS account must
     * ask something account-scoped; `bindsToAccount` below is that question.
     * The returned object carries `scope`, so a caller can tell which of the
     * two answers it got rather than inferring it from a status.
     */
    verifyToken: async () => {
      const accountScoped = await api("GET", "/tokens/verify");
      if (accountScoped.status === 200) return { ...accountScoped, scope: "account" };
      const userScoped = await fetchImpl(`${CF_API}/user/tokens/verify`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}`, "User-Agent": USER_AGENT },
      }).then(
        async (res) => {
          const text = await res.text();
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* non-JSON edge error page */
          }
          return { status: res.status, json, text };
        },
        (err) => ({ status: 0, json: null, text: "", networkError: String(err?.message ?? err) })
      );
      return userScoped.status === 200 ? { ...userScoped, scope: "user" } : { ...accountScoped, scope: "none" };
    },

    /**
     * Does this token reach THIS account, with the permission the publisher
     * cannot work without?
     *
     * Listing Pages projects is the right question to ask (issue #107): it is
     * account-scoped, so a token belonging to another account is refused; it is
     * read-only, so it has no side effect; and `Cloudflare Pages: Edit` -- which
     * every deploy needs regardless of mode -- includes it. A 200 here is the
     * binding `/user/tokens/verify` cannot give.
     *
     * Access is deliberately NOT the probe. `GET /access/apps` answers 200 to a
     * token with no Access permission at all (measured in Glassdocs: the
     * collection is filtered by permission rather than refused), and a missing
     * Access scope is fatal only in gated mode -- so a failure there cannot tell
     * an account problem from a scope one, which is how an agency ended up
     * widening a permission that was already correct.
     */
    bindsToAccount: () => api("GET", "/pages/projects?per_page=1"),

    /**
     * MAY THIS TOKEN SEE CLOUDFLARE ACCESS AT ALL? (issue #118)
     *
     * This REPLACED `accessScopeProbe`, a `GET /access/apps?per_page=1` whose
     * 200 was read as "the token can reach Access". It could not: a token with
     * no Access permission gets a 200 and an empty collection, so the probe
     * passed exactly the credential it existed to flag. It is deleted rather
     * than left in place, because a client method that answers the wrong
     * question is one somebody reaches for again.
     *
     * The question `GET /access/apps` cannot answer. Measured live on Rocket
     * Lab's account, same endpoint, same account, two tokens: one returns 49
     * applications, and a token holding Pages but not Access returns
     * `200 {"success":true,"errors":[],"result":[]}` -- while sites on that
     * account are demonstrably 302ing to cloudflareaccess.com. The collection is
     * FILTERED BY PERMISSION rather than refused, so the absence of an error is
     * not evidence that the caller could look. cf.mjs already recorded that
     * behaviour as the reason Access is not the account-binding probe; it was
     * never applied to the function every security decision calls.
     *
     * So the capability needs a POSITIVE signal, and the one available is
     * already in RECORDED_ERRORS: asking for the policies of an application that
     * does not exist answers `404 / 11021` to a token that may manage Access,
     * and `403 / 10000` to one that may not. Two repos measured the same numbers
     * on four tokens across three accounts.
     *
     * Anything else -- a 500, a rate limit, an HTML error page from the edge --
     * leaves the capability UNPROVEN, and unproven is reported as "could not
     * look". That is the fail-safe direction in both modes: gated refuses to
     * publish on an unverified gate, and public warns instead of silently
     * reporting that a site it cannot see into is ungated.
     *
     * Returns { capable, error }.
     */
    async accessReadCapability() {
      if (accessReadable !== null) return accessReadable;
      const resp = await api("GET", `/access/apps/${ACCESS_CAPABILITY_PROBE_APP}/policies?per_page=1`);
      const code = firstErrorCode(resp);
      const detail = `${firstError(resp)} (HTTP ${resp.status}${code ? `, code ${code}` : ""})`;
      if (resp.status === 404 || code === RECORDED_ERRORS.accessPermissionPresent.code) {
        accessReadable = { capable: true, error: null };
      } else if (resp.status === 403 || code === RECORDED_ERRORS.accountForbidden.code) {
        accessReadable = {
          capable: false,
          error:
            `this Cloudflare token cannot read Access on this account -- ${detail}. Note that the ` +
            `application list itself does NOT fail for such a token: Cloudflare answers it 200 with an ` +
            `empty collection, which is why an empty list is not evidence that no gate exists`,
        };
      } else {
        accessReadable = {
          capable: false,
          error:
            `whether this Cloudflare token can read Access could not be established -- ${detail}. An ` +
            `application list that came back empty therefore proves nothing either way`,
        };
      }
      return accessReadable;
    },

    /**
     * WRITE probe, for gated mode only: create a throwaway Access application
     * and delete it again.
     *
     * A pre-flight with a side effect is a worse pre-flight in every way except
     * the one that matters, which is that it is the only thing Cloudflare will
     * honour as an answer to "can this token create an Access app". There is no
     * capability endpoint: /tokens/verify reports that the token is live, not
     * what it may do, and the permission-groups API describes the account's
     * available groups rather than this token's grants. If a cheaper probe ever
     * appears, prefer it -- the whole of this comment is the reason it does not
     * exist yet.
     *
     * The domain is `<label>.example.com`: RFC 2606 reserves example.com, so it
     * can never be a zone an agency owns and the probe app therefore cannot
     * gate, or fail to gate, anything real -- even in the leak case below. The
     * label is random, so two concurrent runs cannot collide, and the shape
     * mirrors the create-then-delete probe in docs/onboarding.md step 3b that
     * was verified against the live API.
     *
     * Returns { ok, id, error, code, cleaned }. `cleaned: false` means the app
     * was created and NOT removed; the caller must say its id out loud rather
     * than leave an Access application nobody expects on the account.
     */
    async accessWriteProbe(label) {
      const domain = `${label}.example.com`;
      const created = await this.createAccessApp({
        name: label,
        domain,
        self_hosted_domains: [domain],
        type: "self_hosted",
        session_duration: "1h",
      });
      const id = created.json?.result?.id;
      if (!id) {
        return { ok: false, id: null, error: firstError(created), code: firstErrorCode(created), cleaned: true };
      }
      const del = await this.deleteAccessApp(id);
      return { ok: true, id, error: null, code: "", cleaned: ok(del), cleanupError: ok(del) ? null : firstError(del) };
    },

    // ---- Pages projects --------------------------------------------------
    getProject: (name) => api("GET", `/pages/projects/${name}`),
    createProject: (name) => api("POST", "/pages/projects", { name, production_branch: "main" }),
    deleteProject: (name) => api("DELETE", `/pages/projects/${name}`),
    listDeployments: (name) => api("GET", `/pages/projects/${name}/deployments?per_page=10`),
    rollback: (name, deploymentId) =>
      api("POST", `/pages/projects/${name}/deployments/${deploymentId}/rollback`),

    // ---- Access apps -----------------------------------------------------
    listAccessAppsPage: (page) => api("GET", `/access/apps?page=${page}&per_page=50`),
    createAccessApp: (payload) => api("POST", "/access/apps", payload),
    updateAccessApp: (id, payload) => api("PUT", `/access/apps/${id}`, payload),
    deleteAccessApp: (id) => api("DELETE", `/access/apps/${id}`),

    // ---- Access policies -------------------------------------------------
    listPoliciesPage: (appId, page) => api("GET", `/access/apps/${appId}/policies?page=${page}&per_page=50`),
    createPolicy: (appId, payload) => api("POST", `/access/apps/${appId}/policies`, payload),
    deletePolicy: (appId, policyId) => api("DELETE", `/access/apps/${appId}/policies/${policyId}`),

    /**
     * Find the Access app covering `domain`, paginating the whole list.
     *
     * Returns { listOk, app, error }. `listOk: false` means WE COULD NOT LOOK,
     * which is a different fact from "there is no app" and must never be
     * reported as the latter -- the two call for completely different fixes.
     *
     * ISSUE #118. `listOk` used to be keyed off `success === true`, which is a
     * check for an ERROR, and Cloudflare does not send one here: a token with no
     * Access permission gets `200 {"success":true,"result":[]}` and the flag
     * designed to keep the two facts apart never fired. So NOT FINDING AN APP is
     * only reported as "there is no app" once the token has been shown able to
     * see one. Finding a match needs no such proof -- seeing the application IS
     * the proof that the caller could look -- so the common gated path costs
     * nothing, and the probe is asked at most once per client.
     */
    async findAccessApp(domain) {
      let page = 1;
      for (;;) {
        const resp = await this.listAccessAppsPage(page);
        if (resp.json?.success !== true) {
          return { listOk: false, app: null, error: firstError(resp) };
        }
        const results = resp.json?.result ?? [];
        const match = results.find((app) => appMatchesDomain(app, domain));
        if (match) return { listOk: true, app: match, error: null };

        const totalPages = Number(resp.json?.result_info?.total_pages ?? 1);
        if (page >= totalPages || results.length === 0) {
          const capability = await this.accessReadCapability();
          if (!capability.capable) return { listOk: false, app: null, error: capability.error };
          return { listOk: true, app: null, error: null };
        }
        page += 1;
      }
    },

    /** All policies on an app, paginated, with .success checked per page. */
    async listAllPolicies(appId) {
      const all = [];
      let page = 1;
      for (;;) {
        const resp = await this.listPoliciesPage(appId, page);
        if (resp.json?.success !== true) {
          return { listOk: false, policies: [], error: firstError(resp) };
        }
        const results = resp.json?.result ?? [];
        all.push(...results);
        const totalPages = Number(resp.json?.result_info?.total_pages ?? 1);
        if (page >= totalPages || results.length === 0) {
          return { listOk: true, policies: all, error: null };
        }
        page += 1;
      }
    },

    /**
     * The project's own subdomain AND every domain attached to it.
     *
     * The `domains` array is how a custom domain becomes visible to the
     * publisher: Cloudflare lists the project's pages.dev host there alongside
     * anything an agency wired up in the dashboard. Invariant 10 needs the
     * second kind, because an Access app covers only the hosts it names -- a
     * gated project answering on client.com cannot be proven gated by a 302 on
     * pages.dev.
     *
     * Returns { ok, exists, subdomain, domains, error } -- THREE outcomes, not
     * two (issue #120). This used to collapse a 429, a 500, a 403 from an
     * expired token and a genuinely absent project into
     * `{ subdomain: "", domains: [] }`, discarding the status, and the comment
     * above it stated the conflation as a decision. Two invariants switched off
     * silently on any transient Cloudflare error:
     *
     *   invariant 10 -- the refusal of `mode: gated` on a project carrying a
     *     custom domain is gated on `customDomains.length > 0`. An empty array
     *     from a failed read let a project answering on client.com through, so
     *     the unlaunched site went up readable there while the proof collected
     *     its 302 on pages.dev and reported the gate proven.
     *   invariant 12 -- `<project>.pages.dev` became the fallback host, and that
     *     namespace is global: on a collision the plain name belongs to a
     *     DIFFERENT Cloudflare account.
     *
     * This is the same distinction findAccessApp preserves with `listOk`, which
     * is why it is spelled the same way. A 404 is `ok: true, exists: false`: the
     * API answered the question, and the answer is that there is no project.
     */
    async describeProject(projectName) {
      const resp = await this.getProject(projectName);
      if (resp.status === 404) return { ok: true, exists: false, subdomain: "", domains: [], error: null };
      if (!ok(resp)) {
        return { ok: false, exists: false, subdomain: "", domains: [], error: firstError(resp) };
      }
      const result = resp.json?.result ?? null;
      const domains = Array.isArray(result?.domains) ? result.domains.map((d) => String(d)) : [];
      return {
        ok: true,
        exists: true,
        subdomain: result?.subdomain ? String(result.subdomain) : "",
        domains,
        error: null,
      };
    },
  };
}

export function appMatchesDomain(app, domain) {
  if (!app) return false;
  const selfHosted = app.self_hosted_domains ?? [];
  const destinations = (app.destinations ?? []).map((d) => d?.uri);
  return selfHosted.includes(domain) || destinations.includes(domain) || app.domain === domain;
}

export function appHasWildcard(app, domain) {
  return appMatchesDomain(app, `*.${domain}`);
}

/**
 * Unauthenticated GET against the live site. Returns { status, body, location }.
 *
 * status is a string so that "000" (nothing answered at all) stays a first
 * class outcome rather than collapsing into a falsy 0. "Nothing was served"
 * proves neither a gate nor an exposure, and the whole post-deploy decision
 * hinges on keeping it distinct from both.
 *
 * `location` matters once a site answers on more than one host (invariant 11).
 * `www.client.com` redirecting to `client.com` is a healthy, extremely common
 * arrangement, and a proof that read every 3xx as a lock would fail the launch
 * deploy of every agency that set one up. A 3xx to the Access login and a 3xx
 * to the site's own other hostname are different facts, and only the Location
 * header separates them.
 *
 * The User-Agent is load-bearing here, not cosmetic: a WAF or bot rule that
 * turns away an unidentified client answers with a 403 or a challenge, and this
 * function would report that as "not serving content" -- which in gated mode is
 * read as reassurance while the site is in fact readable by every real browser.
 */
export async function probe(url, { fetchImpl = globalThis.fetch, timeoutMs = 15000 } = {}) {
  let res;
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    res = await fetchImpl(url, {
      redirect: "manual",
      headers: { "User-Agent": USER_AGENT },
      signal: controller?.signal,
    });
  } catch {
    return { status: "000", body: "", location: "" };
  } finally {
    if (timer) clearTimeout(timer);
  }
  let body = "";
  try {
    body = await res.text();
  } catch {
    body = "";
  }
  let location = "";
  try {
    location = res.headers?.get?.("location") ?? "";
  } catch {
    location = "";
  }
  return { status: String(res.status), body, location: String(location ?? "") };
}

export function isRedirect(status) {
  return ["301", "302", "303", "307", "308"].includes(String(status));
}

/** The Cloudflare Zero Trust team hostname suffix. Anchored on a label boundary,
 * so `notcloudflareaccess.com` -- a domain anybody can register -- is not it. */
const ACCESS_TEAM_HOST = /(^|\.)cloudflareaccess\.com$/i;
/** Access's own login endpoint, which it serves on the protected host too. */
const ACCESS_LOGIN_PATH = /^\/cdn-cgi\/access\/(login|logout)(\/|$|\?)/i;

/**
 * Does this observation prove a Cloudflare Access gate is in front of the site?
 *
 * ONE helper, used by BOTH branches, and that is the whole point of it existing
 * (issue #102). The gated branch used to accept any 3xx as proof of the gate --
 * it never read `Location` -- while the public branch forty lines away checked
 * the target. A gated site returning `302 -> /home` with zero Access apps on the
 * account exited 0 with the words "This unlaunched site is not readable by the
 * public". The two branches had drifted, and the fail-closed one was the one
 * that had lost the check.
 *
 * A redirect proves a gate only when it goes somewhere that IS the gate:
 *
 *   * the account's Access team host, `<team>.cloudflareaccess.com`, which is
 *     the shape recorded during live verification --
 *     `https://rocketlab-dev.cloudflareaccess.com/cdn-cgi/access/login/...`; or
 *   * the `/cdn-cgi/access/login` path, which Access also serves on the
 *     protected host itself.
 *
 * Everything else -- a 3xx with no Location, a relative one, one to the site's
 * own other path, one to a stranger -- is a SITE-LEVEL redirect served by an
 * origin that Access plainly did not intercept, and it proves nothing. It is not
 * proof of exposure either: nothing was served. The caller must treat it as
 * unproven and ask the Access API, which is authoritative.
 */
export function redirectsToAccessLogin(observation) {
  return accessRedirectKind(observation) !== "";
}

/**
 * WHICH of the two shapes it is, because they are not equally trustworthy
 * (issue #121).
 *
 *   "team-host"   the Location names `<team>.cloudflareaccess.com`. That is a
 *                 hostname the site's own origin does not control and cannot
 *                 make Cloudflare serve, so the observation stands alone.
 *   "login-path"  the Location is `/cdn-cgi/access/login...` on the protected
 *                 host. Access really does serve its login there, which is why
 *                 the arm exists -- and the same path is WRITABLE BY THE THING
 *                 BEING TESTED. A `_redirects` file in the client's site repo
 *                 containing `/*  /cdn-cgi/access/login/anything  302` makes an
 *                 entirely ungated Pages project answer exactly this, on every
 *                 path. The publisher would be asking the site whether it is
 *                 gated, and believing the answer.
 *   ""            neither.
 *
 * The control files can no longer reach the artifact (build-site's deny-list and
 * guard-artifact.mjs), and the proof still does not rely on that being airtight:
 * a caller that gets "login-path" must corroborate it against the Access API
 * before reporting a gate.
 */
export function accessRedirectKind(observation) {
  if (!isRedirect(observation?.status)) return "";
  const raw = String(observation?.location ?? "").trim();
  if (!raw) return "";
  if (ACCESS_TEAM_HOST.test(redirectHost(raw))) return "team-host";
  return ACCESS_LOGIN_PATH.test(redirectPath(raw)) ? "login-path" : "";
}

/**
 * The path of a Location header, absolute or relative, or "" when there is none.
 * A relative Location stays on the same host, which is exactly why the path has
 * to be readable without a host to resolve it against.
 */
export function redirectPath(location) {
  const raw = String(location ?? "").trim();
  if (!raw) return "";
  try {
    return new URL(raw).pathname;
  } catch {
    return raw.startsWith("/") ? raw.split(/[?#]/)[0] : "";
  }
}

/** A human-readable account of what the edge last did, for an operator message. */
export function describeObservation(observation) {
  const status = String(observation?.status ?? "");
  if (!isRedirect(status)) return `HTTP ${status}`;
  const location = String(observation?.location ?? "").trim();
  return location ? `HTTP ${status} redirecting to ${location}` : `HTTP ${status} with no Location header`;
}

/**
 * The host a Location header points at, lowercased, or "" when there isn't one
 * or it is relative. A relative redirect stays on the same host, which is
 * reported as "" rather than guessed at -- the caller decides what that means.
 */
export function redirectHost(location) {
  const raw = String(location ?? "").trim();
  if (!raw) return "";
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * Invariant 7: HTTP 200 is not proof for the public branch. A Cloudflare
 * placeholder page, an Access-branded error page, and a stale unrelated project
 * all answer 200. The only proof that THIS repo's site is live is the response
 * body carrying this repo's own recognition meta.
 */
export function bodyDeclaresRepo(body, repo) {
  if (!body || !repo) return false;
  // READ IT THE WAY A BROWSER DOES (issues #138, #125). This used to accept ANY
  // matching tag found by a regex requiring quoted attributes, which failed in
  // both directions on the same page: a tag inside an HTML COMMENT proved a site
  // was live -- exactly what #138 shipped, where the injector wrote the true tag
  // into a leading comment and the page carried none in the DOM -- while an
  // unquoted tag the browser does read counted for nothing.
  //
  // A page carrying two tags that disagree proves nothing either. It cannot say
  // which repo backs it, so it is not proof that THIS repo's site is what
  // answered, and this function's only job is deciding that (invariant 7).
  const { repo: declared } = declaredSourceRepo(body);
  return declared !== null && declared.toLowerCase() === repo.trim().toLowerCase();
}
