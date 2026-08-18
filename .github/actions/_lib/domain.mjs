// Resolve the domain a Pages project is ACTUALLY served at.
//
// Never derive it from the project name. On a GLOBAL pages.dev name collision
// Cloudflare assigns a suffixed subdomain (<name>-abc.pages.dev), and
// <name>.pages.dev then belongs to a DIFFERENT Cloudflare account. Protecting
// or probing that name-based domain is the worst of both worlds: it green-lights
// an unprotected client site, and it can roll back a perfectly good deployment
// because someone else's domain answered the way ours should not have.

/**
 * Every domain attached to the project that is NOT its own pages.dev host.
 *
 * Pure, because invariant 10 turns on it: in gated mode any such domain is a
 * host the Access app does not name, so the gate cannot be proven there and the
 * publisher refuses to pretend otherwise. Preview hosts (hash.<project>.pages.dev)
 * are covered by the wildcard in the Access app (invariant 4), so they are not
 * custom domains and must not be reported as such.
 */
export function customDomainsOf(domains, subdomain) {
  const own = String(subdomain ?? "").toLowerCase();
  return (domains ?? [])
    .map((d) => String(d).trim())
    .filter((d) => d.length > 0)
    .filter((d) => {
      const host = d.toLowerCase();
      return host !== own && !host.endsWith(".pages.dev") && host !== "pages.dev";
    });
}

/**
 * Every host the Pages project answers on: its own pages.dev subdomain first,
 * then whatever is attached to it. Order matters -- the first entry is the host
 * the publisher created and is therefore the one its corrective action belongs
 * to (ARCHITECTURE.md invariant 6).
 */
export function servingDomains(pagesDomain, customDomains) {
  const out = [];
  for (const d of [pagesDomain, ...(customDomains ?? [])]) {
    const host = String(d ?? "").trim().toLowerCase();
    if (host && !out.includes(host)) out.push(host);
  }
  return out;
}

/**
 * DISCOVER ALWAYS, DECLARE OPTIONALLY, NEVER ATTACH (ARCHITECTURE.md invariant
 * 11, issue #34).
 *
 * Discovery is what catches the case that actually happens: somebody attaches
 * client.com in the Cloudflare dashboard two clicks after launch, and every
 * downstream step goes on treating one pages.dev host as the whole truth.
 * Declaration is optional and exists so the caller can state, in the diffable
 * workflow, which host is the canonical one -- and so a contradiction between
 * the two is a failure rather than a guess (invariant 1: act on proof).
 *
 * The publisher NEVER attaches a domain and never touches DNS. An agency
 * frequently does not hold the client's registrar zone, so an attach is an
 * operation that can only half-succeed, and a half-attached domain is a site
 * that resolves for nobody while CI reports green. Declaring a domain the
 * project does not carry is therefore an error the caller has to fix in
 * Cloudflare, not an instruction for this publisher.
 *
 * Pure. Returns { ok, canonicalHost, serving, warnings, error }.
 */
export function reconcileCustomDomains({ declared, discovered, projectExists, pagesDomain }) {
  const wanted = String(declared ?? "").trim().toLowerCase();
  const found = (discovered ?? []).map((d) => String(d).trim().toLowerCase()).filter(Boolean);
  const serving = servingDomains(pagesDomain, found);
  const warnings = [];
  const fail = (error) => ({ ok: false, canonicalHost: "", serving, warnings, error });

  if (!wanted) {
    if (found.length === 0) {
      return { ok: true, canonicalHost: String(pagesDomain).toLowerCase(), serving, warnings, error: null };
    }
    if (found.length === 1) {
      // Reported in both modes, per issue #34: a domain nobody declared is still
      // a domain this site is served at, and the canonical URL has to name it or
      // the client's own domain ranks as a duplicate of ours.
      warnings.push(
        `Custom domain '${found[0]}' is attached to this Pages project but the caller workflow never ` +
          `declared it. The publisher found it and is using it as this site's canonical host. Add ` +
          `\`custom-domain: ${found[0]}\` to the caller's \`with:\` block so the intent is in the diff ` +
          `rather than in somebody's dashboard.`
      );
      return { ok: true, canonicalHost: found[0], serving, warnings, error: null };
    }
    return fail(
      `This Pages project answers on ${found.length} custom domains (${found.join(", ")}) and the caller ` +
        `workflow declared none, so there is no way to tell which one is the client's real site. A ` +
        `canonical URL has to name exactly one host: pick wrong and every page tells search engines ` +
        `the authoritative copy lives somewhere the client does not consider primary. Add ` +
        `\`custom-domain: <the one you mean>\` to the caller's \`with:\` block. NOTHING WAS UPLOADED ` +
        `and nothing was changed in Cloudflare.`
    );
  }

  if (!projectExists) {
    warnings.push(
      `Declared custom domain '${wanted}' could not be checked against Cloudflare: the Pages project ` +
        `could not be read. Using it as the canonical host anyway, because the alternative is stamping ` +
        `a pages.dev URL onto a site the caller says lives at ${wanted}.`
    );
    return { ok: true, canonicalHost: wanted, serving: servingDomains(pagesDomain, [wanted]), warnings, error: null };
  }

  if (!found.includes(wanted)) {
    return fail(
      `The caller declared \`custom-domain: ${wanted}\`, and the Cloudflare Pages project does not ` +
        `carry that domain${found.length ? ` (it carries ${found.join(", ")})` : " (it carries none)"}. ` +
        `The publisher does NOT attach domains and does not touch DNS -- an agency often does not hold ` +
        `the client's registrar zone, and a half-attached domain resolves for nobody while the deploy ` +
        `reports green. Attach ${wanted} in the Cloudflare dashboard (Workers & Pages -> the project -> ` +
        `Custom domains), confirm it serves, then re-run. NOTHING WAS UPLOADED.`
    );
  }

  const extras = found.filter((d) => d !== wanted);
  if (extras.length > 0) {
    warnings.push(
      `This project also answers on ${extras.join(", ")}, which the caller did not declare. Those hosts ` +
        `serve the same site and are proven alongside it, but '${wanted}' is the canonical one.`
    );
  }
  return { ok: true, canonicalHost: wanted, serving, warnings, error: null };
}

/**
 * The host this project is served at, or NOTHING.
 *
 * Returns { domain, readOk, projectExists, customDomains }. An empty `domain` is
 * a first-class outcome and every caller has to handle it: there is no host to
 * gate, to stamp, or to probe, and the two ways of reaching that state need
 * different messages.
 *
 *   readOk: false   the Pages project could not be READ -- a 429, a 500, an
 *                   expired token. `customDomains` is empty because nothing was
 *                   observed, NOT because the project carries none, so invariant
 *                   10's refusal cannot be evaluated and a caller must not
 *                   proceed as though it had been (issue #120).
 *   readOk: true, domain: ""
 *                   the API answered and the project has no `.subdomain`: it
 *                   does not exist, or it was created seconds ago.
 *
 * NOTHING here falls back to `${projectName}.pages.dev`. That construction is
 * what this file exists to refuse, and it was reachable on any transient
 * Cloudflare error, on a project that already had a perfectly good subdomain,
 * under a log line saying "has no subdomain yet" -- a state the run never
 * observed (invariant 12, issue #120).
 */
export async function resolveDomain(cf, projectName, logger) {
  const described = await cf.describeProject(projectName);
  const customDomains = customDomainsOf(described.domains, described.subdomain);

  if (!described.ok) {
    logger.warning(
      `The Cloudflare Pages project '${projectName}' could not be read (${described.error}), so the ` +
        `host it is served at, and every custom domain attached to it, are unknown to this run. That ` +
        `is NOT the same as a project with no domains: the publisher will not guess ` +
        `'${projectName}.pages.dev', because that name is global and on a collision it belongs to a ` +
        `different Cloudflare account.`
    );
    return { domain: "", readOk: false, projectExists: false, customDomains: [] };
  }

  if (!described.subdomain) {
    logger.info(
      `Cloudflare reports no .subdomain for Pages project '${projectName}'` +
        `${described.exists ? "" : " (there is no such project)"} -- this run has no host for it.`
    );
    return { domain: "", readOk: true, projectExists: false, customDomains };
  }

  const nameBased = `${projectName}.pages.dev`;
  if (described.subdomain !== nameBased) {
    logger.warning(
      `pages.dev name collision: this project is really served at ${described.subdomain}, not ` +
        `${nameBased} (the plain name is taken by another Cloudflare account). Everything downstream ` +
        `-- the Access app and the post-deploy proof -- uses the real domain. To get the clean URL, ` +
        `delete this Pages project and redeploy once the plain name is free.`
    );
  }
  return { domain: described.subdomain, readOk: true, projectExists: true, customDomains };
}
