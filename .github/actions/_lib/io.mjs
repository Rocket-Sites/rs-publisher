// Logging and Actions plumbing, kept behind an object so every script in this
// directory can be driven from a unit test with no GitHub Actions runner and no
// stdout noise. The workflow annotations (::error::, ::warning::, ::notice::)
// are what an agency actually sees when a deploy goes wrong, so the tests
// assert on them the same way a human would read them.

import fs from "node:fs";

export function createLogger({ stream = process.stdout, capture = false } = {}) {
  const lines = [];
  const emit = (line) => {
    lines.push(line);
    if (!capture) stream.write(line + "\n");
  };
  return {
    lines,
    // Everything that was printed, joined. Tests match against this rather than
    // against a specific call, because the message is the deliverable.
    text: () => lines.join("\n"),
    info: (msg) => emit(String(msg)),
    notice: (msg) => emit(`::notice::${msg}`),
    warning: (msg) => emit(`::warning::${msg}`),
    error: (msg) => emit(`::error::${msg}`),
    // file/line annotation, so the agency sees which page is wrong rather than
    // "the deploy failed".
    errorAt: (file, line, msg) => emit(`::error file=${file},line=${line}::${msg}`),
  };
}

// Step outputs. In a test there is no GITHUB_OUTPUT, so the values are only
// collected and handed back to the caller for assertion.
export function createOutputs(env = process.env) {
  const values = {};
  const path = env.GITHUB_OUTPUT;
  return {
    values,
    set(name, value) {
      values[name] = String(value);
      if (path) fs.appendFileSync(path, `${name}=${value}\n`);
    },
  };
}

export const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Read a value with NO fallback default. Deliberately distinct from
// `env.X || 'something'`: an input that was set to the empty string on purpose
// must stay empty. A default that fills in for an explicitly blank access input
// is how a site silently re-broadens who can see it.
export function readExplicit(env, name) {
  return env[name] === undefined ? "" : String(env[name]);
}

// Seconds override used ONLY as a test seam. Nothing sets these in CI or in
// production; the caller's default is the shipped value.
export function seconds(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}
