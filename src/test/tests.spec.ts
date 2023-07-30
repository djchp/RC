import { readAndValidateAssets, readAndValidatePlatforms, readAndValidateVulnerabilities } from "../index";

describe("tests", () => {
  describe("test functions responsible for reading and validating JSON files", () => {
    it("should throw reading platform error", async () => {
      await expect(async () => {
        await readAndValidatePlatforms()
      }).rejects.toThrow();
    });
    it("should throw reading asset error", async () => {
      await expect(async () => {
        await readAndValidateAssets()
      }).rejects.toThrow();
    });
    it("should throw reading Vuln error", async () => {
      await expect(async () => {
        await readAndValidateVulnerabilities()
      }).rejects.toThrow();
    });
  });
});
