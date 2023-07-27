export interface PlatformRelation {
  platformId: string;
  minVersion: string;
  maxVersion: string;
}

export interface Asset {
  id: string;
  name: string;
  platformRelations: PlatformRelation[];
}

export interface Vulnerability {
  id: string;
  name: string;
  platformRelations: PlatformRelation[];
}

export interface Platform {
  id: string;
  name: string;
}

export interface AssetVulnerabilityPair {
  assetId: string;
  vulnerabilityId: string;
  commonPlatform: string;
}

