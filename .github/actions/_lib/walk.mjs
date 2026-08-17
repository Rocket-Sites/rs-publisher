// The one walk over the publish directory, and the one rule about what may be
// in it: REGULAR FILES.
//
// ── Why this is a shared module and not three loops (issue #141) ──────────
//
// There were three copies of the same walk -- `htmlFiles` in
// inject-source-meta.mjs, and an `allFiles` in each of the two artifact guards
// -- and all three asked `entry.isDirectory()` and treated everything else as a
// plain file. `readdirSync(..., { withFileTypes: true })` lstats, so a symbolic
// link is not a directory, and a symlink was therefore walked as a file by every
// one of them. Executed, in a site repo containing `evil.html -> ../outside.txt`:
//
//   WRITE   `runInjectSourceMeta` and `runStampSiteUrl` open the entry for
//           writing, so the bytes land in the TARGET. A meta tag and a canonical
//           tag were prepended to a file outside the publish directory by a job
//           holding the agency's account-wide Cloudflare token. On a
//           GitHub-hosted runner the blast radius is the ephemeral VM; on a
//           self-hosted one -- which no document here forbids, and which an
//           agency running forty sites may well move to -- it is an
//           arbitrary-file-prepend on the agency's own machine.
//   BYPASS  a symlinked DIRECTORY is worse than a symlinked file, because it is
//           classified as one plain entry with an unrecognised extension: never
//           recursed into, so NOTHING under it is checked by any rule in either
//           guard, while `rsync -a` preserved the link and the upload follows
//           it. `assets -> ../.git` publishes the repository's git objects to
//           the client's live site, past a deny-list that excludes `.git` by
//           name.
//   READ    the guards read the target's bytes. What is checked and what is
//           served are then two different files, decided at two different
//           moments.
//
// So the walk refuses rather than skips, and it refuses ANY non-regular entry
// rather than trying to decide which links are safe. "It points inside the
// publish directory" is a property of the target at the instant it is read, and
// a publisher that reasons about that is a publisher discovering the answer on a
// client's live site.
//
// The refusal is a backstop. `rsync --no-links` in build-site/action.yml is what
// stops a link being assembled in the first place, for the same reason the Pages
// control files are both excluded and guarded: an agency should not have a run
// fail over a file they never meant to ship.

import fs from "node:fs";
import path from "node:path";

/** What a link points at, without following it. "" if it cannot be read. */
function linkTarget(full) {
  try {
    return fs.readlinkSync(full);
  } catch {
    return "";
  }
}

/**
 * Every regular file under `dir`, and every entry that is NOT one.
 *
 * Returns `{ files, refused }`. `refused` entries carry `{ path, kind, target }`
 * and are never followed, never read, and never counted as files -- a caller
 * that ignores them is publishing bytes nothing checked.
 */
export function walkArtifact(dir) {
  const files = [];
  const refused = [];
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isSymbolicLink()) {
        refused.push({ path: full, kind: "symbolic link", target: linkTarget(full) });
        continue;
      }
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (entry.isFile()) {
        files.push(full);
        continue;
      }
      // A fifo, a socket, a device node. Nothing a marketing site is made of,
      // and reading one can block the runner forever.
      refused.push({ path: full, kind: "not a regular file", target: "" });
    }
  };
  walk(dir);
  return { files, refused };
}

/** Every regular `.html`/`.htm` file under `dir`. */
export function htmlFiles(dir) {
  return walkArtifact(dir).files.filter((f) => /\.html?$/i.test(f));
}

/** Every regular file under `dir`, whatever its extension. */
export function allFiles(dir) {
  return walkArtifact(dir).files;
}

/**
 * The message an operator gets, in one place because three steps say it.
 *
 * It names what the link is and what it points at, because the two failures it
 * covers look nothing alike from the outside: a link to a file publishes
 * somebody else's bytes under the client's domain, and a link to a directory
 * publishes a whole tree that no rule in either guard ever looked at.
 */
export function refusalMessage(entry) {
  const target = entry.target ? ` pointing at '${entry.target}'` : "";
  return (
    `is a ${entry.kind}${target}, and the publisher publishes files. A link is resolved by three ` +
    `different processes at three different moments: the stamping steps write THROUGH it, so the bytes ` +
    `land outside the publish directory; the guards read the TARGET's bytes, so what is checked and what ` +
    `is served are different files; and a link to a DIRECTORY is not walked into at all, so nothing ` +
    `under it is checked by any rule here while the upload serves all of it. The upload directory is ` +
    `assembled with 'rsync --no-links', so a link cannot arrive from the site repo -- finding one here ` +
    `means something created it after assembly. Replace it with the real file.`
  );
}

/**
 * Report every refused entry through the caller's own failure channel.
 *
 * `report(file, line, message)` is whatever the step already uses for a
 * file-and-line annotation, so an agency sees the same shape of message it sees
 * for every other artifact problem. Returns how many were reported, so a caller
 * can decide to stop before it writes anything.
 */
export function reportRefusals(refused, report) {
  for (const entry of refused) report(entry.path, 1, refusalMessage(entry));
  return refused.length;
}
