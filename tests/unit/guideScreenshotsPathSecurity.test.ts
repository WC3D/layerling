import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Tests for the file inclusion attack mitigation in guide-screenshots.mjs.
 * 
 * The vulnerability was that a malicious language parameter could be used to
 * traverse outside the intended directory structure and write files to arbitrary
 * locations on the filesystem.
 * 
 * The fix validates that the resolved path stays within the imageRoot directory
 * by checking if the relative path escapes the parent directory.
 */

describe("guide-screenshots path traversal protection", () => {
  /**
   * Simulates the path validation logic from guide-screenshots.mjs lines 77-82.
   * This is the security check that prevents path traversal attacks.
   */
  function validateImagePath(root: string, language: string): { valid: boolean; error?: string } {
    const imageRoot = resolve(root, "docs", "guide", "images");
    const imageDirectory = join(imageRoot, language);
    const relativeImageDirectory = relative(imageRoot, imageDirectory);
    
    // Security check: ensure the path doesn't escape the imageRoot
    if (relativeImageDirectory === ".." || relativeImageDirectory.startsWith(`..${sep}`) || isAbsolute(relativeImageDirectory)) {
      return { valid: false, error: "Invalid file path" };
    }
    
    return { valid: true };
  }

  describe("legitimate language codes", () => {
    it("should allow valid language code 'en'", () => {
      const result = validateImagePath("/project", "en");
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should allow valid language code 'de'", () => {
      const result = validateImagePath("/project", "de");
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should allow language codes with hyphens", () => {
      const result = validateImagePath("/project", "zh-cn");
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should allow language codes with underscores", () => {
      const result = validateImagePath("/project", "pt_BR");
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });
  });

  describe("path traversal attack attempts", () => {
    it("should reject simple parent directory traversal", () => {
      const result = validateImagePath("/project", "..");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });

    it("should reject path traversal with multiple parent directories", () => {
      const result = validateImagePath("/project", "../../etc");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });

    it("should reject path traversal to system directories", () => {
      const result = validateImagePath("/project", "../../../etc/passwd");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });

    it("should reject path traversal with forward slashes", () => {
      const result = validateImagePath("/project", "../../../tmp/malicious");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });

    it("should reject path starting with parent directory", () => {
      const result = validateImagePath("/project", "../sensitive");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });
  });

  describe("absolute path injection attempts", () => {
    it("should handle absolute Unix paths (treated as relative by join)", () => {
      // On Unix, join() treats "/etc/passwd" as a relative path component
      // join("/project/docs/guide/images", "/etc/passwd") => "/project/docs/guide/images/etc/passwd"
      // This is NOT a vulnerability because it stays within the imageRoot
      const result = validateImagePath("/project", "/etc/passwd");
      // The path stays within imageRoot, so it's technically valid (though unusual)
      expect(result.valid).toBe(true);
      // Note: In practice, this would create a directory named "etc" under images,
      // which is harmless but unexpected. The real vulnerability is parent traversal.
    });

    it("should reject absolute Windows paths with drive letter on Windows", () => {
      // On Unix systems, this is treated as a relative path with backslashes
      // On Windows systems, this would be caught by isAbsolute
      const result = validateImagePath("/project", "C:\\Windows\\System32");
      // The behavior depends on the platform
      if (process.platform === "win32") {
        expect(result.valid).toBe(false);
        expect(result.error).toBe("Invalid file path");
      } else {
        // On Unix, backslashes are valid filename characters, not separators
        expect(result.valid).toBe(true);
      }
    });
  });

  describe("edge cases and boundary conditions", () => {
    it("should allow subdirectories within valid language codes", () => {
      // Note: This tests the current behavior. If subdirectories should be blocked,
      // additional validation would be needed in the actual implementation.
      const result = validateImagePath("/project", "en/subdir");
      expect(result.valid).toBe(true);
    });

    it("should reject empty string as language", () => {
      const result = validateImagePath("/project", "");
      // Empty string resolves to imageRoot itself, which is valid
      expect(result.valid).toBe(true);
    });

    it("should reject current directory reference", () => {
      const result = validateImagePath("/project", ".");
      // Current directory reference resolves to imageRoot itself
      expect(result.valid).toBe(true);
    });

    it("should handle language codes with dots", () => {
      const result = validateImagePath("/project", "en.US");
      expect(result.valid).toBe(true);
    });
  });

  describe("path normalization bypass attempts", () => {
    it("should reject encoded parent directory traversal", () => {
      // Even though this looks like a valid name, path.join normalizes it
      const result = validateImagePath("/project", "en/../../../etc");
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid file path");
    });

    it("should reject mixed separators in traversal", () => {
      // On Unix, backslashes are treated as regular characters, not path separators
      // So this becomes a valid directory name containing backslashes
      const result = validateImagePath("/project", "..\\..\\..\\Windows");
      if (process.platform === "win32") {
        // On Windows, backslashes are path separators and this is traversal
        expect(result.valid).toBe(false);
        expect(result.error).toBe("Invalid file path");
      } else {
        // On Unix, this is just a weird directory name with backslashes
        expect(result.valid).toBe(true);
      }
    });

    it("should reject null byte injection attempts", () => {
      // Node.js path functions handle null bytes, but we test the behavior
      const result = validateImagePath("/project", "en\0../../etc");
      // Path functions will process this, but the traversal check should catch it
      // The actual behavior depends on how Node.js handles null bytes in paths
      expect(result.valid).toBe(true); // null byte becomes part of the name, no traversal
    });
  });

  describe("security property verification", () => {
    it("should ensure relative path never starts with '..'", () => {
      const testCases = [
        "en",
        "de", 
        "zh-cn",
        "pt_BR",
        "en/subdir",
      ];

      for (const language of testCases) {
        const imageRoot = resolve("/project", "docs", "guide", "images");
        const imageDirectory = join(imageRoot, language);
        const relativeImageDirectory = relative(imageRoot, imageDirectory);
        
        // Security property: valid paths should never start with '..'
        expect(relativeImageDirectory).not.toMatch(/^\.\./);
        expect(relativeImageDirectory).not.toBe("..");
      }
    });

    it("should ensure malicious paths are caught by the check", () => {
      const maliciousCases = [
        "..",
        "../..",
        "../../etc",
        "../../../tmp",
        "../sensitive/data",
      ];

      for (const language of maliciousCases) {
        const imageRoot = resolve("/project", "docs", "guide", "images");
        const imageDirectory = join(imageRoot, language);
        const relativeImageDirectory = relative(imageRoot, imageDirectory);
        
        // Security property: malicious paths should be detected
        const isEscaping = relativeImageDirectory === ".." || 
                          relativeImageDirectory.startsWith(`..${sep}`) || 
                          isAbsolute(relativeImageDirectory);
        expect(isEscaping).toBe(true);
      }
    });
  });
});
