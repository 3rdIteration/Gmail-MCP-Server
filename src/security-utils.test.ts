import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  EMAIL_CONTENT_SECURITY_NOTICE,
  bestEffortHtmlToText,
  ensurePrivateDirectoryPermissions,
  ensurePrivateFilePermissions,
  extractSafeEmailBody,
  getSafeErrorMessage,
  renderQuotedUntrustedBlock,
  sanitizeUntrustedText,
  validateRedirectUri,
} from "./security-utils.js";

describe("security-utils email content handling", () => {
  it("exposes a fixed security notice for untrusted email content", () => {
    expect(EMAIL_CONTENT_SECURITY_NOTICE).toContain("untrusted content");
  });

  it("sanitizes single-line header values", () => {
    expect(sanitizeUntrustedText("  Hello\r\nWorld\t", { singleLine: true })).toBe("Hello World");
  });

  it("quotes multiline body content for safer framing", () => {
    expect(renderQuotedUntrustedBlock("line 1\nline 2")).toBe("| line 1\n| line 2");
  });

  it("strips comments, hidden content, and scripts from HTML", () => {
    const html = `
      <html>
        <body>
          Visible text
          <!-- hidden instruction -->
          <div style="display:none">invisible</div>
          <script>alert("bad")</script>
          <p>More&nbsp;text</p>
        </body>
      </html>
    `;

    const text = bestEffortHtmlToText(html);
    expect(text).toContain("Visible text");
    expect(text).toContain("More text");
    expect(text).not.toContain("hidden instruction");
    expect(text).not.toContain("invisible");
    expect(text).not.toContain("alert");
  });

  it("falls back to sanitized HTML-derived text when plain text is missing", () => {
    const result = extractSafeEmailBody({
      text: "",
      html: "<div>Hello</div><!--ignore--><div style='display:none'>secret</div>",
    });

    expect(result.body).toContain("Hello");
    expect(result.body).not.toContain("secret");
    expect(result.note).toContain("HTML");
  });
});

describe("security-utils auth and error hardening", () => {
  it("redacts tokens and auth codes from surfaced errors", () => {
    const error = new Error(
      'Request failed: access_token=abc123 refresh_token=def456 Bearer xyz789 https://example.com?code=qwerty'
    );

    const sanitized = getSafeErrorMessage(error);
    expect(sanitized).not.toContain("abc123");
    expect(sanitized).not.toContain("def456");
    expect(sanitized).not.toContain("xyz789");
    expect(sanitized).not.toContain("qwerty");
    expect(sanitized).toContain("[REDACTED]");
  });

  it("requires callback URLs to match configured redirect URIs", () => {
    expect(
      validateRedirectUri("https://gmail.example.com/oauth2callback", [
        "https://gmail.example.com/oauth2callback",
      ])
    ).toBe("https://gmail.example.com/oauth2callback");

    expect(() =>
      validateRedirectUri("https://attacker.example.com/oauth2callback", [
        "https://gmail.example.com/oauth2callback",
      ])
    ).toThrow("must exactly match");
  });

  it("applies private permissions to created config directories and files", () => {
    if (process.platform === "win32") {
      const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gmail-mcp-security-"));
      const dirPath = path.join(tmpRoot, "config");
      const filePath = path.join(dirPath, "credentials.json");

      expect(() => ensurePrivateDirectoryPermissions(dirPath)).not.toThrow();
      fs.writeFileSync(filePath, "{}");
      expect(() => ensurePrivateFilePermissions(filePath)).not.toThrow();
      return;
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gmail-mcp-security-"));
    const dirPath = path.join(tmpRoot, "config");
    const filePath = path.join(dirPath, "credentials.json");

    ensurePrivateDirectoryPermissions(dirPath);
    fs.writeFileSync(filePath, "{}");
    ensurePrivateFilePermissions(filePath);

    expect(fs.statSync(dirPath).mode & 0o777).toBe(0o700);
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
  });
});
