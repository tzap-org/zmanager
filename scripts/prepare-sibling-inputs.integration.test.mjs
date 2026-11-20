import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const repositoryRoot = join(import.meta.dirname, "..");
const resolverSource = join(repositoryRoot, "scripts", "prepare-sibling-inputs.sh");
const bash = process.env.BASH ?? "bash";

function command(executable, args, options = {}) {
  return execFileSync(executable, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

function git(directory, ...args) {
  return command("git", args, { cwd: directory });
}

function createFixture(t) {
  const root = mkdtempSync(join(tmpdir(), "zmanager-build-inputs-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const workspace = join(root, "workspace");
  const scripts = join(workspace, "scripts");
  const parent = join(root, "siblings");
  mkdirSync(scripts, { recursive: true });
  mkdirSync(parent, { recursive: true });
  const resolver = join(scripts, "prepare-sibling-inputs.sh");
  writeFileSync(resolver, readFileSync(resolverSource));

  const seed = join(root, "seed");
  const remote = join(root, "remote.git");
  git(root, "init", "--bare", "--initial-branch=main", remote);
  git(root, "init", "--initial-branch=main", seed);
  git(seed, "config", "user.name", "Build Inputs Test");
  git(seed, "config", "user.email", "build-inputs@example.invalid");
  writeFileSync(join(seed, "tracked.txt"), "initial\n");
  git(seed, "add", "tracked.txt");
  git(seed, "commit", "-m", "initial");
  git(seed, "remote", "add", "origin", remote);
  git(seed, "push", "origin", "main");
  const revision = git(seed, "rev-parse", "HEAD");

  const repoUrl = "https://fixture.invalid/tzap.git";
  const catalog = join(workspace, "inputs.lock");
  writeFileSync(catalog, `tzap ${repoUrl} main ${revision}\n`);
  git(workspace, "init", "--initial-branch=main");
  git(workspace, "config", "user.name", "Build Inputs Test");
  git(workspace, "config", "user.email", "build-inputs@example.invalid");
  git(workspace, "add", "scripts/prepare-sibling-inputs.sh", "inputs.lock");
  git(workspace, "commit", "-m", "fixture workspace");
  const env = {
    ...process.env,
    ZMANAGER_SIBLING_PARENT_DIR: parent,
  };

  return { catalog, env, parent, remote, repoUrl, resolver, revision, root, seed, workspace };
}

function setRemoteUrl(fixture, checkout) {
  git(checkout, "remote", "set-url", "origin", fixture.repoUrl);
}

function localCloneEnvironment(fixture) {
  const shimDirectory = join(fixture.root, "git-shim");
  mkdirSync(shimDirectory);
  const realGit = command("which", ["git"]);
  const shim = join(shimDirectory, "git");
  writeFileSync(shim, `#!/bin/sh
if [ "$1" = clone ]; then
  for destination do :; done
  "$REAL_GIT" clone "$LOCAL_REMOTE" "$destination" || exit $?
  "$REAL_GIT" -C "$destination" remote set-url origin "$CANONICAL_ORIGIN"
else
  exec "$REAL_GIT" "$@"
fi
`);
  chmodSync(shim, 0o755);
  return {
    REAL_GIT: realGit,
    LOCAL_REMOTE: fixture.remote,
    CANONICAL_ORIGIN: fixture.repoUrl,
    PATH: `${shimDirectory}:${process.env.PATH}`,
  };
}

function initCheckout(fixture) {
  const checkout = join(fixture.parent, "tzap");
  command("git", ["clone", fixture.remote, checkout], { cwd: fixture.parent });
  git(checkout, "config", "user.name", "Build Inputs Test");
  git(checkout, "config", "user.email", "build-inputs@example.invalid");
  // The resolver validates the canonical HTTPS URL; existing checkouts need
  // only contain the requested commit, so use the fixture's local object store.
  setRemoteUrl(fixture, checkout);
  return checkout;
}

function runResolver(fixture, args, env = fixture.env) {
  return command(bash, [fixture.resolver, "--lockfile", fixture.catalog, ...args], {
    cwd: fixture.workspace,
    env,
  });
}

test("CI resolver captures the configured branch head in a snapshot lock", (t) => {
  const fixture = createFixture(t);
  const gitConfig = join(fixture.root, "gitconfig");
  git(fixture.root, "config", "--file", gitConfig, "--add", `url.file://${fixture.remote}.insteadOf`, fixture.repoUrl);
  const env = { ...fixture.env, GIT_CONFIG_GLOBAL: gitConfig };
  const output = join(fixture.root, "ci-snapshot.lock");

  runResolver(fixture, ["--resolve-ci", output], env);

  const entry = readFileSync(output, "utf8").split(/\r?\n/).find((line) => line.startsWith("tzap "));
  assert.equal(entry, `tzap ${fixture.repoUrl} main ${fixture.revision}`);
});

test("snapshot mode reports the GitHub revision when a container checkout has no .git directory", (t) => {
  const fixture = createFixture(t);
  initCheckout(fixture);
  rmSync(join(fixture.workspace, ".git"), { recursive: true, force: true });
  const env = {
    ...fixture.env,
    GITHUB_SHA: fixture.revision,
    GITHUB_REPOSITORY: "tzap-org/build-inputs-test",
  };

  runResolver(fixture, ["--mode", "snapshot"], env);

  const desktopRow = readFileSync(join(fixture.workspace, "target", "build-inputs-report.tsv"), "utf8")
    .split(/\r?\n/)[1]
    .split("\t");
  assert.equal(desktopRow[3], "DETACHED");
  assert.equal(desktopRow[4], fixture.revision);
  assert.equal(desktopRow[5], "clean");
  assert.equal(desktopRow[6], "snapshot");
  assert.equal(desktopRow[1], "https://github.com/tzap-org/build-inputs-test");
});

test("snapshot mode clones a missing sibling cleanly before checking out its pinned SHA", (t) => {
  // On Windows Git records the rewritten file:// URL as origin during clone,
  // which correctly fails the resolver's canonical-origin validation. The
  // CI resolver runs on Ubuntu, where Git preserves the HTTPS origin.
  if (process.platform === "win32") {
    t.skip("Git for Windows records rewritten file:// clone URLs as origin");
    return;
  }

  const fixture = createFixture(t);
  const env = { ...fixture.env, ...localCloneEnvironment(fixture) };
  const checkout = join(fixture.parent, "tzap");

  runResolver(fixture, ["--mode", "snapshot"], env);

  assert.equal(git(checkout, "rev-parse", "HEAD"), fixture.revision);
  assert.equal(git(checkout, "branch", "--show-current"), "");
  assert.equal(git(checkout, "status", "--porcelain=v1", "--untracked-files=all"), "");
});

test("snapshot mode detaches at the requested commit and rejects dirty checkouts", (t) => {
  const fixture = createFixture(t);
  const checkout = initCheckout(fixture);

  runResolver(fixture, ["--mode", "snapshot"]);
  assert.equal(git(checkout, "rev-parse", "HEAD"), fixture.revision);
  assert.equal(git(checkout, "branch", "--show-current"), "");

  writeFileSync(join(checkout, "tracked.txt"), "preserve this edit\n");
  assert.throws(
    () => runResolver(fixture, ["--mode", "snapshot"]),
    (error) => /has local changes/.test(`${error.stdout}\n${error.stderr}`),
  );
  assert.equal(readFileSync(join(checkout, "tracked.txt"), "utf8"), "preserve this edit\n");
});

test("local mode preserves dirty sibling work and records its actual head", (t) => {
  const fixture = createFixture(t);
  const checkout = initCheckout(fixture);
  writeFileSync(join(checkout, "tracked.txt"), "local iteration\n");
  const report = join(fixture.root, "report.tsv");

  runResolver(fixture, ["--mode", "local", "--report", report]);

  assert.equal(git(checkout, "rev-parse", "HEAD"), fixture.revision);
  assert.equal(readFileSync(join(checkout, "tracked.txt"), "utf8"), "local iteration\n");
  assert.match(readFileSync(report, "utf8"), /^tzap\t.*\tmain\tmain\t[0-9a-f]{40}\tdirty\tlocal\t/m);
});
