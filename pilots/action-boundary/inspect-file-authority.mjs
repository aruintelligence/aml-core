// Read-only operator snapshot. Never clears a lock or edits authority state.
import { createFileAuthorityAnchor, inspectFileRevocationHandoff } from
  "./file-revocation-handoff.mjs";

const [directory, anchorDirectory, ...extra] = process.argv.slice(2);
if (!directory || extra.length) {
  process.stderr.write("Usage: node inspect-file-authority.mjs ABS_AUTHORITY_DIR [ABS_ANCHOR_DIR]\n");
  process.exitCode = 2;
} else {
  try {
    const anchor = anchorDirectory ? createFileAuthorityAnchor({
      directory: anchorDirectory, create: false
    }) : null;
    const report = inspectFileRevocationHandoff({ directory, anchor });
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    if (report.status !== "observed_consistent") process.exitCode = 2;
  } catch (error) {
    process.stdout.write(JSON.stringify({ protocol: "aml-file-authority-inspection/1",
      status: "inspection_unavailable", reason: error.message }) + "\n");
    process.exitCode = 2;
  }
}
