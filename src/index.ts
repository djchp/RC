import { createReadStream, promises as fs, createWriteStream } from "fs";
import {
  Asset,
  AssetVulnerabilityPair,
  Platform,
  Vulnerability,
} from "./types/main-types";
import Ajv, { JSONSchemaType } from "ajv";
import path from "path";
import dotenv from "dotenv";
import JSONStream from "jsonstream";
import IntervalTree from "node-interval-tree";
import compareVersions from "compare-versions";
import { EOL } from "os";
dotenv.config();

const ajv = new Ajv();


async function ReadJsonFile<T>(filePath: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath, "utf8");
    const parser = JSONStream.parse("*");

    const data: any[] = [];

    stream
      .pipe(parser)
      .on("data", (item: any) => {
        data.push(item);
      })
      .on("end", () => {
        resolve(data as T);
      })
      .on("error", reject);
  });
}

async function WriteResultToJsonFile<T>(
  fileName: string,
  dataArray: T[]
): Promise<void> {
  const outputFilePath = path.join(process.cwd(), fileName);
  try {
    const writeStream = createWriteStream(outputFilePath, "utf8");
    writeStream.write("[" + EOL);
    dataArray.forEach((item, index) => {
      writeStream.write(
        JSON.stringify(item) + (index < dataArray.length - 1 ? "," + EOL : "")
      );
    });
    writeStream.write(EOL + "]");
    writeStream.end();
    console.log(`Data written to ${outputFilePath} successfully.`);
  } catch (err) {
    console.error(`Error writing to ${outputFilePath}: ${err}`);
  }
}

export async function readAndValidatePlatforms() {
  try {
    const platforms = (await ReadJsonFile(
      `${process.env.PLATFORM_PATH}`
    )) as Platform[];
    const platformSchema: JSONSchemaType<Platform[]> = {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
        },
        required: ["id", "name"],
      },
    };
    const validatePlatforms = ajv.compile(platformSchema);
    if (!validatePlatforms(platforms)) {
      throw new Error("Platform data does not match the expected schema.");
    }
    return platforms;
  } catch (error: any) {
    throw new Error(error.message);
  }
}
export async function readAndValidateAssets() {
  try {
    const assets = (await ReadJsonFile(`${process.env.ASSET_PATH}`)) as Asset[];
    const assetSchema: JSONSchemaType<Asset[]> = {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          platformRelations: {
            type: "array",
            items: {
              type: "object",
              properties: {
                platformId: { type: "string" },
                minVersion: { type: "string" },
                maxVersion: { type: "string" },
              },
              required: ["platformId", "minVersion", "maxVersion"],
            },
          },
        },
        required: ["id", "name", "platformRelations"],
      },
    };
    const validateAssets = ajv.compile(assetSchema);
    if (!validateAssets(assets)) {
      throw new Error("Asset data does not match the expected schema.");
    }
    return assets;
  } catch (error: any) {
    throw new Error(error.message);
  }
}
export async function readAndValidateVulnerabilities() {
  try {
    const vulnerabilities = (await ReadJsonFile(
      `${process.env.VULN_PATH}`
    )) as Vulnerability[];
    const vulnerabilitySchema: JSONSchemaType<Vulnerability[]> = {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          platformRelations: {
            type: "array",
            items: {
              type: "object",
              properties: {
                platformId: { type: "string" },
                minVersion: { type: "string" },
                maxVersion: { type: "string" },
              },
              required: ["platformId", "minVersion", "maxVersion"],
            },
          },
        },
        required: ["id", "name", "platformRelations"],
      },
    };
    const validateVulnerabilities = ajv.compile(vulnerabilitySchema);
    if (!validateVulnerabilities(vulnerabilities)) {
      throw new Error(
        "Vulnerabilities data does not match the expected schema."
      );
    }
    return vulnerabilities;
  } catch (error: any) {
    throw new Error(error.message);
  }
}

async function calculatePairs(
  platforms: Platform[],
  assets: Asset[],
  vulnerabilities: Vulnerability[]
) {
  const pairs: AssetVulnerabilityPair[] = [];
  const platformHelperMap = new Map(
    platforms.map((platform) => [platform.id, platform.name])
  );

  const assetPlatformMap: Map<string, [string, string, string][]> = new Map();
  assets.forEach((asset) => {
    asset.platformRelations.forEach((platformRelation) => {
      const platformData =
        assetPlatformMap.get(platformRelation.platformId) || [];
      platformData.push([
        asset.id,
        platformRelation.minVersion,
        platformRelation.maxVersion,
      ]);
      assetPlatformMap.set(platformRelation.platformId, platformData);
    });
  });
  const assetPlatformIntervalTrees: Map<
    string,
    IntervalTree<string>
  > = new Map();
  for (const [platformId, assetData] of assetPlatformMap) {
    const tree = new IntervalTree<string>();
    for (const [assetId, minVersion, maxVersion] of assetData) {
      if (compareVersions.compare(minVersion, maxVersion, "<=")) {
        tree.insert(parseFloat(minVersion), parseFloat(maxVersion), assetId);
      } else {
        console.error(
          `Invalid version range for asset ${assetId}: ${minVersion} to ${maxVersion}`
        );
      }
    }

    assetPlatformIntervalTrees.set(platformId, tree);
  }

  for (const vulnerability of vulnerabilities) {
    for (const platformRelation of vulnerability.platformRelations) {
      const platformID = platformRelation.platformId;
      const vulnerabilityMinVersion = parseFloat(platformRelation.minVersion);
      const vulnerabilityMaxVersion = parseFloat(platformRelation.maxVersion);

      let matchingAssets;
      let holder;
      if ((holder = assetPlatformIntervalTrees.get(platformID))) {
        const commonPlatform = platformHelperMap.get(platformID);
        matchingAssets = holder.search(
          vulnerabilityMinVersion,
          vulnerabilityMaxVersion
        );
        for (const assetID of matchingAssets) {
          pairs.push({
            assetId: assetID,
            vulnerabilityId: vulnerability.id,
            commonPlatform: commonPlatform ? commonPlatform : "asd",
          });
        }
      }
    }
  }

  return pairs;
}

async function main() {
  console.time("execution_time:");
  try {
    const [platforms, assets, vulnerabilities] = await Promise.all([
      readAndValidatePlatforms(),
      readAndValidateAssets(),
      readAndValidateVulnerabilities(),
    ]);
    if (!platforms || !assets || !vulnerabilities) {
      throw new Error(
        "One or more given inputs have wrong format or property missing"
      );
    }
    const result = await calculatePairs(platforms, assets, vulnerabilities);
    await WriteResultToJsonFile<AssetVulnerabilityPair>("output.json", result);
  } catch (error: any) {
    console.error("An error occurred:", error.message);
  }
  console.timeEnd("execution_time:");
}
main();
