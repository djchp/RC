import { promises as fs } from "fs";
import {
  Asset,
  AssetVulnerabilityPair,
  Platform,
  Vulnerability,
} from "./types/main-types";
import Ajv, { JSONSchemaType } from "ajv";
import compareVersions from "compare-versions";
import Piscina from "piscina";
import { chunk } from "lodash";
import path from "path";
const ajv = new Ajv();

async function ReadJsonFile<T>(filePath: string): Promise<T> {
  const data = await fs.readFile(filePath, "utf8");
  return JSON.parse(data) as T;
}

async function readAndValidatePlatforms() {
  try {
    const platforms = (await ReadJsonFile(
      "./files/Platforms.json"
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
    console.error("Error occurred:", error.message);
  }
}
async function readAndValidateAssets() {
  try {
    const assets = (await ReadJsonFile("./files/Assets.json")) as Asset[];
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
    console.error("Error occurred:", error.message);
  }
}
async function readAndValidateVulnerabilities() {
  try {
    const vulnerabilities = (await ReadJsonFile(
      "./files/Vulnerabilities.json"
    )) as Asset[];
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
    console.error("Error occurred:", error.message);
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

  const assetPlatformMap = new Map();
  assets.forEach((asset) => {
    asset.platformRelations.forEach((platformRelation) => {
      const minMaxVersion = [
        platformRelation.minVersion,
        platformRelation.maxVersion,
      ];
      const platformData =
        assetPlatformMap.get(platformRelation.platformId) || [];
      platformData.push([asset.id, ...minMaxVersion]);
      assetPlatformMap.set(platformRelation.platformId, platformData);
    });
  });

  const piscina = new Piscina({
    filename: path.resolve(__dirname, 'worker.js')
  });
  const chunkSize = Math.ceil(vulnerabilities.length / 4);
  const vulnerabilitiesChunks = chunk(vulnerabilities, chunkSize);
  const tasks = vulnerabilitiesChunks.map((vulnerabilitiesChunk) =>
    piscina.run({
      assetPlatformMap: Array.from(assetPlatformMap), 
      platformHelperMap: Array.from(platformHelperMap), 
      vulnerabilitiesChunk,
    })
  );
  const results = await Promise.all(tasks);
  results.map((result) => {
    pairs.push(...result);
  });

  return pairs;
}

async function main() {
  try {
    const platforms = await readAndValidatePlatforms();
    const assets = await readAndValidateAssets();
    const vulnerabilities = await readAndValidateVulnerabilities();
    if (!platforms || !assets || !vulnerabilities) {
      throw new Error(
        "One or more given inputs have wrong format or property missing"
      );
    }
    const result = await calculatePairs(platforms, assets, vulnerabilities);
    console.log(result);
  } catch (error: any) {
    console.error("An error occurred:", error.message);
  }
}
main();