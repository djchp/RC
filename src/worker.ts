// just leaving it here so you know i thought about pararell processing 


// import compareVersions from "compare-versions";
// import IntervalTree from "node-interval-tree";

// type Version = string;
// type PlatformID = string;
// type AssetID = string;
// type VulnerabilityID = string;

// type PlatformHelperMap = [PlatformID, string][];
// type AssetPlatformMap = [PlatformID, [AssetID, Version, Version][]][];

// type Vulnerability = {
//   id: VulnerabilityID;
//   platformRelations: {
//     platformId: PlatformID;
//     minVersion: Version;
//     maxVersion: Version;
//   }[];
// };

// interface WorkerData {
//   assetPlatformMap: AssetPlatformMap;
//   platformHelperMap: PlatformHelperMap;
//   vulnerabilities: any;
// }

// export default ({
//   assetPlatformMap,
//   platformHelperMap,
//   vulnerabilities,
// }: WorkerData) => {
//   const platformHelperMapConverted = new Map(platformHelperMap);
//   const assetPlatformIntervalTrees: Map<
//     string,
//     IntervalTree<string>
//   > = new Map();
//   for (const [platformId, assetData] of assetPlatformMap) {
//     const tree = new IntervalTree<string>();
//     for (const [assetId, minVersion, maxVersion] of assetData) {
//       if (compareVersions.compare(minVersion, maxVersion, "<=")) {
//         tree.insert(parseFloat(minVersion), parseFloat(maxVersion), assetId);
//       } else {
//         console.error(
//           `Invalid version range for asset ${assetId}: ${minVersion} to ${maxVersion}`
//         );
//       }
//     }

//     assetPlatformIntervalTrees.set(platformId, tree);
//   }

//   const assetVulnerabilityPairs: any = [];
//   for (const vulnerability of vulnerabilities) {
//     for (const platformRelation of vulnerability.platformRelations) {
//       const platformID = platformRelation.platformId;
//       const vulnerabilityMinVersion = parseFloat(platformRelation.minVersion);
//       const vulnerabilityMaxVersion = parseFloat(platformRelation.maxVersion);

//       let matchingAssets;
//       let holder;
//       if ((holder = assetPlatformIntervalTrees.get(platformID))) {
//         matchingAssets = holder.search(
//           vulnerabilityMinVersion,
//           vulnerabilityMaxVersion
//         );
//         for (const assetID of matchingAssets) {
//           assetVulnerabilityPairs.push({
//             assetID: assetID,
//             vulnerabilityID: vulnerability.id,
//             platformName: platformHelperMapConverted.get(platformID), // Assuming platformsMap is the mapping between platform ID and name
//           });
//         }
//       }
//     }
//   }
//   return assetVulnerabilityPairs;
// };
