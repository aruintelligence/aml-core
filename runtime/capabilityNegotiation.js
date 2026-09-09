import { highestCommonProtocolVersion } from "../protocol/versionOrder.js";

export function negotiateCapabilities(local, remote, { required = [] } = {}) {
  const normalize = (value = []) => [...new Set(value)].sort();
  const localCaps = normalize(local?.capabilities);
  const remoteCaps = normalize(remote?.capabilities);
  const remoteSet = new Set(remoteCaps);
  const common = localCaps.filter((cap) => remoteSet.has(cap));
  const missingRequired = normalize(required).filter((cap) => !common.includes(cap));

  const localVersions = [...new Set(local?.versions || [local?.version].filter(Boolean))];
  const remoteVersions = [...new Set(remote?.versions || [remote?.version].filter(Boolean))];
  const { selected: selectedVersion } = highestCommonProtocolVersion(localVersions, remoteVersions);

  return {
    protocol: "aml-capability-negotiation/1",
    compatible: missingRequired.length === 0 && Boolean(selectedVersion),
    selected_version: selectedVersion,
    common_capabilities: common,
    missing_required: missingRequired,
    local_only: localCaps.filter((cap) => !remoteSet.has(cap)),
    remote_only: remoteCaps.filter((cap) => !new Set(localCaps).has(cap))
  };
}
