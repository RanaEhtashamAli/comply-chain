import type { Page } from "@playwright/test";

export interface CapturedDownload {
  filename: string;
  body: Buffer;
}

/** Runs `trigger`, waits for the resulting download, and buffers its bytes. */
export async function captureDownload(
  page: Page,
  trigger: () => Promise<void>
): Promise<CapturedDownload> {
  const [download] = await Promise.all([page.waitForEvent("download"), trigger()]);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return { filename: download.suggestedFilename(), body: Buffer.concat(chunks) };
}
