import { parentPort } from "worker_threads";
import compareVersions from "compare-versions";

type Version = string;
type PlatformID = string;
type AssetID = string;
type VulnerabilityID = string;

type PlatformHelperMap = [PlatformID, string][];
type AssetPlatformMap = [PlatformID, [AssetID, Version, Version][]][];

type Vulnerability = {
  id: VulnerabilityID;
  platformRelations: {
    platformId: PlatformID;
    minVersion: Version;
    maxVersion: Version;
  }[];
};

interface WorkerData {
  assetPlatformMap: AssetPlatformMap;
  platformHelperMap: PlatformHelperMap;
  vulnerabilitiesChunk: Vulnerability[];
}

export default ({
  assetPlatformMap,
  platformHelperMap,
  vulnerabilitiesChunk,
}: WorkerData) => {
  const assetPlatformMapConverted = new Map(assetPlatformMap);
  const platformHelperMapConverted = new Map(platformHelperMap);

  const pairs = [];

  for (const vulnerability of vulnerabilitiesChunk) {
    for (const vulnerabilityPlatform of vulnerability.platformRelations) {
      const assetData = assetPlatformMapConverted.get(
        vulnerabilityPlatform.platformId
      );
      if (assetData) {
        const vulnerabilityMinVersion = vulnerabilityPlatform.minVersion;
        const vulnerabilityMaxVersion = vulnerabilityPlatform.maxVersion;
        const commonPlatformName = platformHelperMapConverted.get(
          vulnerabilityPlatform.platformId
        );

        if (commonPlatformName) {
          for (const [assetId, assetMinVersion, assetMaxVersion] of assetData) {
            if (
              compareVersions.compare(
                assetMinVersion,
                vulnerabilityMaxVersion,
                "<="
              ) &&
              compareVersions.compare(
                assetMaxVersion,
                vulnerabilityMinVersion,
                ">="
              )
            ) {
              pairs.push({
                assetId: assetId,
                vulnerabilityId: vulnerability.id,
                commonPlatform: commonPlatformName,
              });
            }
          }
        }
      }
    }
  }

  return pairs;
};
