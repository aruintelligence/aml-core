import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));

export function getSourceState() {
  // A runner environment variable can name a different commit. Read the
  // checkout that actually supplies the pilot code and fixtures instead.
  const source_revision = execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]
  }).trim();
  const diff = spawnSync("git", ["diff", "--quiet", "HEAD", "--"], {
    cwd: root, encoding: "utf8"
  });
  if (diff.status !== 0 && diff.status !== 1) {
    throw new Error("cannot inspect tracked source changes");
  }
  return { source_revision, tracked_worktree_modified: diff.status === 1 };
}
