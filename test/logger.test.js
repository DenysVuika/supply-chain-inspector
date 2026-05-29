import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { log, logOk, logErr, logWarn } from "../logger.js";

describe("logger", () => {
  let stderrSpy;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => {});
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  describe("log()", () => {
    it("writes the message followed by a newline to stderr", () => {
      log("hello world");
      expect(stderrSpy).toHaveBeenCalledOnce();
      expect(stderrSpy).toHaveBeenCalledWith("hello world\n");
    });

    it("writes an empty string message", () => {
      log("");
      expect(stderrSpy).toHaveBeenCalledWith("\n");
    });
  });

  describe("logOk()", () => {
    it("prefixes the message with the ✓ success marker", () => {
      logOk("all good");
      expect(stderrSpy).toHaveBeenCalledWith("  ✓ all good\n");
    });
  });

  describe("logErr()", () => {
    it("prefixes the message with the ✗ error marker", () => {
      logErr("something broke");
      expect(stderrSpy).toHaveBeenCalledWith("  ✗ something broke\n");
    });
  });

  describe("logWarn()", () => {
    it("prefixes the message with the ⚠ warning marker", () => {
      logWarn("watch out");
      expect(stderrSpy).toHaveBeenCalledWith("  ⚠ watch out\n");
    });
  });
});
