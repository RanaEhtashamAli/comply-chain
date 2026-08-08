import { expect } from "@playwright/test";
import { createHash } from "node:crypto";
import AdmZip from "adm-zip";
import { XMLParser } from "fast-xml-parser";

const MIN_PDF_BYTES = 1024;

export function expectPdf(body: Buffer, label: string): void {
  expect(body.subarray(0, 5).toString("latin1"), `${label} should start with %PDF-`).toBe("%PDF-");
  expect(body.byteLength, `${label} should exceed ${MIN_PDF_BYTES} bytes`).toBeGreaterThan(
    MIN_PDF_BYTES
  );
}

export interface SarXml {
  EFilingBatchXML: {
    FormData: {
      ReportHeader: { BSAID: string | number; FilingType: string; ReportType: string };
      NarrativeSection: { Narrative: string };
    };
  };
}

export function parseSarXml(body: Buffer): SarXml {
  const parser = new XMLParser({ ignoreAttributes: false });
  return parser.parse(body.toString("utf-8")) as SarXml;
}

/** Opens the ZIP and verifies every hash in manifest.json against its member. */
export function expectEvidenceZip(body: Buffer): Record<string, unknown> {
  const zip = new AdmZip(body);
  const names = zip.getEntries().map((e) => e.entryName);
  expect(names, "evidence ZIP should contain manifest.json").toContain("manifest.json");

  const manifest = JSON.parse(zip.readAsText("manifest.json")) as {
    sha256_hashes: Record<string, string>;
  };
  expect(Object.keys(manifest.sha256_hashes).length, "manifest should list files").toBeGreaterThan(0);

  for (const [name, expected] of Object.entries(manifest.sha256_hashes)) {
    const entry = zip.getEntry(name);
    expect(entry, `manifest lists "${name}" but the ZIP has no such member`).toBeTruthy();
    const actual = createHash("sha256").update(entry!.getData()).digest("hex");
    expect(actual, `SHA-256 mismatch for "${name}"`).toBe(expected);
  }

  return manifest as unknown as Record<string, unknown>;
}
