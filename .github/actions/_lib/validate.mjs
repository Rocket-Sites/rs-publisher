// Pure input validation. No network, no side effects, no I/O. Everything here
// runs before anything in a publish has happened, because the alternative --
// discovering a malformed email only when Cloudflare rejects the create, after
// the old policies were already deleted -- is how a site ends up gated to
// nobody with no way back.

export const MODES = ["public", "gated"];

export function isValidMode(mode) {
  return MODES.includes(mode);
}

// Cloudflare Pages project names are [a-z0-9-]. Rejecting anything else stops
// argument and JSON injection where the name arrives as a repo variable set by
// a human or by the extension, with no server-side validation in front of it.
export function isValidProjectName(name) {
  return typeof name === "string" && /^[a-z0-9-]+$/.test(name);
}

// Split a comma-separated list, tolerating newlines. A plain split on "," is
// not enough: a value pasted one-per-line into a repo variable, or written as a
// YAML block scalar, must yield every address rather than the first one -- and
// a value that STARTS with a newline must not yield zero items, because zero
// grants on a gated site means gated to nobody.
export function splitList(raw) {
  if (raw === undefined || raw === null) return [];
  return String(raw)
    .replace(/\r/g, ",")
    .replace(/\n/g, ",")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Deliberately conservative. An address Cloudflare would reject must be
// rejected here instead, before any mutation.
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;

export function isValidEmail(value) {
  return EMAIL_RE.test(value);
}

export function isValidEmailDomain(value) {
  return DOMAIN_RE.test(value) && !value.includes("@");
}

// A custom domain is a BARE HOSTNAME: no scheme, no path, no port. It is
// compared against what Cloudflare reports on the Pages project and it is
// interpolated into an absolute URL stamped onto every published page, so
// "https://client.com/" arriving here would produce a canonical of
// "https://https://client.com//about" on a live client site.
export function isValidCustomDomain(value) {
  return typeof value === "string" && value.length <= 253 && DOMAIN_RE.test(value) && !value.includes("@");
}

// The set of access inputs. Named once so the "public mode must not carry
// access inputs" check and the "gated to nobody" warning cannot drift apart.
export const ACCESS_INPUT_NAMES = ["agency-domain", "client-domain", "client-emails"];

/**
 * `wrangler-version` -- an exact semver, or empty (issue #123).
 *
 * This was the ONE caller input that reached a third party without passing
 * through here. `cloudflare/wrangler-action` interpolates it into
 * `npm install wrangler@<version>`, which means an npm spec: `latest` is a
 * floating tag, and a git URL or a file path installs arbitrary code into the
 * job that holds the agency's Cloudflare API token. It is not shell-injectable
 * at the pinned SHA, because upstream builds an argv array -- but "not
 * exploitable at the version we happen to run today" is a property of somebody
 * else's code, and until #123 the action was on a moving tag, so it could change
 * without notice.
 *
 * Empty is the normal case and means "whatever wrangler-action picks". A RANGE
 * is deliberately refused: `^3` is not a pin, and the whole point of naming a
 * version is to get the same one twice.
 */
export function isValidWranglerVersion(value) {
  if (typeof value !== "string") return false;
  if (value.trim() === "") return true;
  return /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(value.trim());
}
