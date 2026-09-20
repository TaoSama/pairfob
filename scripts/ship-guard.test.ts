import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

const guard = new URL("./ship-guard.sh", import.meta.url).pathname;
const releaseFiles = [
  "pairfob-darwin-amd64",
  "pairfob-darwin-arm64",
  "pairfob-linux-amd64",
  "pairfob-linux-arm64",
];

function run(body: string, env: Record<string, string> = {}): { exit: number; stderr: string } {
  const proc = Bun.spawnSync(["bash", "-c", `set -euo pipefail; . "$GUARD"; ${body}`], {
    env: { ...process.env, ...env, GUARD: guard },
    stderr: "pipe",
    stdout: "pipe",
  });
  return { exit: proc.exitCode ?? 1, stderr: proc.stderr.toString() };
}

function releaseFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "pairfob-release-"));
  for (const name of releaseFiles) {
    writeFileSync(join(dir, name), `fixture ${name}\n`);
    chmodSync(join(dir, name), 0o755);
  }
  writeFileSync(join(dir, "VERSION"), "1.0.0\n");
  const manifest = [...releaseFiles, "VERSION"]
    .map((name) => `${createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")}  ${name}`)
    .join("\n");
  writeFileSync(join(dir, "SHA256SUMS"), `${manifest}\n`);
  return dir;
}

describe("ship-guard version", () => {
  test("accepts SemVer with or without a v prefix", () => {
    expect(run(`pairfob_require_shipable_version "1.0.0"`).exit).toBe(0);
    expect(run(`pairfob_require_shipable_version "v1.2.3"`).exit).toBe(0);
  });

  test("refuses hashes, date stamps, empty, dev, and dirty labels", () => {
    for (const v of ["", "dev", "578a90b", "578a90b-dirty", "2026-08-29.3", "v1.0.0-1-g578a90b"]) {
      const got = run(`pairfob_require_shipable_version "${v}" "VERSION"`);
      expect(got.exit, v).not.toBe(0);
      expect(got.stderr).toContain("not shippable");
    }
  });

  test("PAIRFOB_ALLOW_DIRTY is local-only bypass", () => {
    expect(run(`pairfob_require_shipable_version "dev"`, { PAIRFOB_ALLOW_DIRTY: "1" }).exit).toBe(0);
  });

  test("a VERSION file is required when packing /dl", () => {
    const dir = mkdtempSync(join(tmpdir(), "pairfob-dl-"));
    expect(run(`pairfob_require_shipable_version_file "${dir}/VERSION"`).exit).not.toBe(0);
    writeFileSync(join(dir, "VERSION"), "dev\n");
    expect(run(`pairfob_require_shipable_version_file "${dir}/VERSION"`).exit).not.toBe(0);
    writeFileSync(join(dir, "VERSION"), "ad27e83\n");
    expect(run(`pairfob_require_shipable_version_file "${dir}/VERSION"`).exit).not.toBe(0);
    writeFileSync(join(dir, "VERSION"), "1.0.0\n");
    expect(run(`pairfob_require_shipable_version_file "${dir}/VERSION"`).exit).toBe(0);
  });
});

describe("ship-guard clean tree", () => {
  test("refuses a dirty repo and accepts a clean one", () => {
    const dir = mkdtempSync(join(tmpdir(), "pairfob-tree-"));
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src/a.txt"), "a\n");
    const git = (args: string) =>
      Bun.spawnSync(["bash", "-c", `git -C "$DIR" ${args}`], {
        env: { ...process.env, DIR: dir, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" },
      });
    git("init -q");
    git("add src/a.txt");
    git('commit -qm init');
    expect(run(`pairfob_require_clean_tree "${dir}"`).exit).toBe(0);
    writeFileSync(join(dir, "src/a.txt"), "b\n");
    const dirty = run(`pairfob_require_clean_tree "${dir}"`);
    expect(dirty.exit).not.toBe(0);
    expect(dirty.stderr).toContain("working tree is dirty");
    expect(run(`pairfob_require_clean_tree "${dir}"`, { PAIRFOB_ALLOW_DIRTY: "1" }).exit).toBe(0);
  });
});

describe("ship-guard release directory", () => {
  test("accepts only the complete pairfob artifact set", () => {
    const dir = releaseFixture();
    expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: dir }).exit).toBe(0);
  });

  test("rejects legacy pairfobd artifacts and any other extra file", () => {
    for (const extra of ["pairfobd-darwin-arm64", "notes.txt"]) {
      const dir = releaseFixture();
      writeFileSync(join(dir, extra), "stale\n");
      expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: dir }).exit, extra).not.toBe(0);
    }
  });

  test("rejects missing or symlinked binaries", () => {
    const missing = releaseFixture();
    rmSync(join(missing, releaseFiles[0]));
    expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: missing }).exit).not.toBe(0);

    const linked = releaseFixture();
    rmSync(join(linked, releaseFiles[0]));
    symlinkSync(releaseFiles[1], join(linked, releaseFiles[0]));
    expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: linked }).exit).not.toBe(0);
  });

  test("rejects corrupt content and malformed manifests", () => {
    const corrupt = releaseFixture();
    writeFileSync(join(corrupt, releaseFiles[0]), "changed after checksums\n");
    expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: corrupt }).exit).not.toBe(0);

    const malformed = releaseFixture();
    writeFileSync(join(malformed, "SHA256SUMS"), `${"0".repeat(64)}  pairfobd-darwin-arm64\n`);
    expect(run(`pairfob_require_release_dir "$DIR"`, { DIR: malformed }).exit).not.toBe(0);
  });
});

describe("release and pack call the guard", () => {
  test("release.sh refuses a dirty tree before it compiles", () => {
    const release = readFileSync(new URL("./release.sh", import.meta.url), "utf8");
    expect(release).toContain('ship-guard.sh');
    expect(release).toContain("pairfob_require_clean_tree");
    expect(release).toContain("pairfob_require_shipable_version");
    expect(release).toContain("pairfob_require_release_dir");
    expect(release).toContain("describe --tags --exact-match");
    expect(release).toContain("requires semver");
  });

  test("pack with PAIRFOB_PACK_DL=1 requires a complete release directory", () => {
    const pack = readFileSync(new URL("./pack-origin-assets.sh", import.meta.url), "utf8");
    expect(pack).toContain("pairfob_require_release_dir");
    expect(pack).not.toMatch(/PAIRFOB_PACK_DL:-\}" == "1" && -d/);
  });
});

/**
 * Verifying the pack must not write the tree that is about to be deployed.
 *
 * The pack removes its destination outright and only restores `dl/` when asked
 * for binaries, so a validation run aimed at `public-dist` strips `/dl` from an
 * already-correct deploy tree. That happened: the release check, `pairfob
 * update` and install.sh all resolve `<origin>/dl/VERSION`, and all three broke.
 *
 * These cases cannot run the pack to completion -- it needs `pwa/dist` and runs
 * a full VitePress build, and this file executes before the PWA is built -- so
 * they evaluate the real assignment line and the real guard instead, and assert
 * on the wiring in verify.sh. What that leaves unproven is the byte-for-byte
 * survival of public-dist across a full verify run; the strongest available
 * proxy is that verify.sh no longer names the deploy tree at all.
 */
describe("the pack destination", () => {
  const packPath = new URL("./pack-origin-assets.sh", import.meta.url).pathname;
  const verifyPath = new URL("./verify.sh", import.meta.url).pathname;

  /** Evaluate the script's own DEST line, so a renamed var or a swapped `:-` fails here. */
  function resolveDEST(env: Record<string, string> = {}): string {
    const script = 'set -euo pipefail; ROOT=/repo; eval "$(grep -m1 \'^DEST=\' "$PACK")"; printf %s "$DEST"';
    const proc = Bun.spawnSync(["bash", "-c", script], {
      env: { ...process.env, ...env, PACK: packPath },
      stdout: "pipe",
      stderr: "pipe",
    });
    if ((proc.exitCode ?? 1) !== 0) throw new Error(proc.stderr.toString());
    return proc.stdout.toString();
  }

  test("defaults to the deployable public-dist", () => {
    expect(resolveDEST()).toBe("/repo/workers/pairfob-origin/public-dist");
  });

  test("PAIRFOB_PACK_DEST redirects the pack", () => {
    expect(resolveDEST({ PAIRFOB_PACK_DEST: "/scratch/pack" })).toBe("/scratch/pack");
  });

  test("an empty override falls back instead of leaving the destination blank", () => {
    // `rm -rf ""` is harmless but `mkdir -p "/css"` is not, so the fallback has
    // to be `:-` rather than `-`.
    expect(resolveDEST({ PAIRFOB_PACK_DEST: "" })).toBe("/repo/workers/pairfob-origin/public-dist");
  });

  test("a relative destination is refused before anything is deleted", () => {
    const proc = Bun.spawnSync(["bash", packPath], {
      env: { ...process.env, PAIRFOB_PACK_DEST: "relative/dir" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(proc.exitCode ?? 0).not.toBe(0);
    expect(proc.stderr.toString()).toContain("must be an absolute path");
  });

  test("a destination the pack does not own is refused", () => {
    // An allowlist, not a denylist: `rm -rf` gets this value, so anything
    // outside the repo is refused rather than only the paths someone thought to
    // name. `..` and symlinks are resolved first, so a path that merely reads as
    // if it were inside the tree cannot escape it.
    const repoRoot = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
    const outside = ["/", "/etc", "/tmp", process.env.HOME ?? "/root", `${repoRoot}/../escape`, repoRoot];
    for (const dest of outside) {
      const proc = Bun.spawnSync(["bash", packPath], {
        env: { ...process.env, PAIRFOB_PACK_DEST: dest },
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(proc.exitCode ?? 0).not.toBe(0);
      expect(proc.stderr.toString()).toContain("refusing to pack into");
    }
  });

  test("a destination inside the repo is accepted", () => {
    // The guard must not be so strict that the scratch dir verify.sh relies on
    // stops working -- including when HOME is a symlink, which is the case on
    // the machines this is developed on.
    const repoRoot = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
    const probe = `${repoRoot}/.tmp/guard-probe`;
    try {
      const proc = Bun.spawnSync(["bash", packPath], {
        env: { ...process.env, PAIRFOB_PACK_DEST: probe },
        stdout: "pipe",
        stderr: "pipe",
      });
      const stderr = proc.stderr.toString();
      expect(stderr).not.toContain("refusing to pack into");
      expect(stderr).not.toContain("must be an absolute path");
      // It may still fail later for want of a PWA build; only the guard is under
      // test here, and the guard runs before that precondition.
      expect(stderr).toContain("PAIRFOB_PACK_DEST override");
    } finally {
      rmSync(probe, { recursive: true, force: true });
    }
  });

  test("verify.sh packs into scratch and never names the deploy tree", () => {
    const verify = readFileSync(verifyPath, "utf8");
    expect(verify).not.toContain("workers/pairfob-origin/public-dist");
    expect(verify).toContain('trap \'rm -rf "$PACK_DEST"\' EXIT');

    const calls = verify
      .split("\n")
      .filter((line) => line.includes("pack-origin-assets.sh"))
      .filter((line) => !line.trimStart().startsWith("#") && !line.includes("bash -n"));
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call).toContain("PAIRFOB_PACK_DEST=");
      // Binaries stay out so the Worker e2e stays small (release.sh:58).
      expect(call).not.toContain("PAIRFOB_PACK_DL");
    }
  });
});
