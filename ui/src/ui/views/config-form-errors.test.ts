/**
 * Tests for form error accessibility components
 */

import { describe, it, expect } from "vitest";
import {
  getErrorId,
  getFieldId,
  buildDescribedBy,
  ValidationMessages,
  type FieldError,
} from "./config-form-errors.js";

describe("config-form-errors", () => {
  describe("getErrorId", () => {
    it("should generate error ID from path", () => {
      expect(getErrorId("api.key")).toBe("error-api-key");
      expect(getErrorId("config[0].name")).toBe("error-config-0--name");
    });

    it("should handle paths with special characters", () => {
      expect(getErrorId("nested.deep.value")).toBe("error-nested-deep-value");
    });
  });

  describe("getFieldId", () => {
    it("should generate field ID from path", () => {
      expect(getFieldId("api.key")).toBe("field-api-key");
      expect(getFieldId("items[0]")).toBe("field-items-0-");
    });
  });

  describe("buildDescribedBy", () => {
    it("should combine help and error IDs", () => {
      expect(buildDescribedBy({ helpId: "help-1", errorId: "error-1" })).toBe("help-1 error-1");
    });

    it("should return only help ID when no error", () => {
      expect(buildDescribedBy({ helpId: "help-1" })).toBe("help-1");
    });

    it("should return only error ID when no help", () => {
      expect(buildDescribedBy({ errorId: "error-1" })).toBe("error-1");
    });

    it("should return undefined when no IDs", () => {
      expect(buildDescribedBy({})).toBeUndefined();
    });
  });

  describe("ValidationMessages", () => {
    it("should generate required error", () => {
      const error = ValidationMessages.required("API Key");
      expect(error.message).toContain("required");
      expect(error.suggestion).toContain("enter a value");
    });

    it("should generate type error", () => {
      const error = ValidationMessages.type("Port", "number", "string");
      expect(error.message).toContain("must be a number");
      expect(error.suggestion).toContain("number");
    });

    it("should generate minLength error", () => {
      const error = ValidationMessages.minLength("Password", 8);
      expect(error.message).toContain("at least 8 characters");
    });

    it("should generate maxLength error", () => {
      const error = ValidationMessages.maxLength("Username", 20);
      expect(error.message).toContain("no more than 20 characters");
    });

    it("should generate minimum error", () => {
      const error = ValidationMessages.minimum("Age", 18);
      expect(error.message).toContain("at least 18");
    });

    it("should generate maximum error", () => {
      const error = ValidationMessages.maximum("Score", 100);
      expect(error.message).toContain("no more than 100");
    });

    it("should generate pattern error", () => {
      const error = ValidationMessages.pattern("Email", "Use format: user@example.com");
      expect(error.message).toContain("format is invalid");
      expect(error.suggestion).toContain("user@example.com");
    });

    it("should generate pattern error with default suggestion", () => {
      const error = ValidationMessages.pattern("Code");
      expect(error.suggestion).toContain("check the format");
    });

    it("should generate enum error", () => {
      const error = ValidationMessages.enum("Status", ["active", "inactive", "pending"]);
      expect(error.message).toContain("allowed values");
      expect(error.suggestion).toContain("active, inactive, pending");
    });

    it("should generate unsupported error", () => {
      const error = ValidationMessages.unsupported("Custom Field");
      expect(error.message).toContain("unsupported");
      expect(error.suggestion).toContain("Raw JSON");
    });

    it("should generate generic error", () => {
      const error = ValidationMessages.generic("Field");
      expect(error.message).toContain("has an error");
    });
  });

  describe("FieldError interface", () => {
    it("should accept complete error object", () => {
      const error: FieldError = {
        path: "config.api.key",
        field: "API Key",
        message: "Invalid API key format",
        suggestion: "Check your API key and try again",
      };

      expect(error.path).toBe("config.api.key");
      expect(error.field).toBe("API Key");
      expect(error.message).toBe("Invalid API key format");
      expect(error.suggestion).toBe("Check your API key and try again");
    });

    it("should accept error without suggestion", () => {
      const error: FieldError = {
        path: "name",
        field: "Name",
        message: "Required",
      };

      expect(error.suggestion).toBeUndefined();
    });
  });
});
