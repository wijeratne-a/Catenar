import { blake3 } from "hash-wasm";

type AnchorResult = {
  anchor_url: string;
  anchored_at: string;
};

export async function blake3Commitment(payload: unknown): Promise<string> {
  const normalized = JSON.stringify(payload);
  const digest = await blake3(normalized);
  return `0x${digest}`;
}

export async function publishCommitment(
  commitment: string,
  metadata: Record<string, unknown>
): Promise<AnchorResult> {
  const anchoredAt = new Date().toISOString();
  const githubToken = process.env.GITHUB_TOKEN;
  const gistId = process.env.GITHUB_GIST_ID;

  if (!githubToken || !gistId) {
    return {
      anchor_url: `https://example.com/aegis-anchor/${commitment}`,
      anchored_at: anchoredAt,
    };
  }

  const filename = `aegis-${commitment.slice(2, 14)}.json`;
  const content = JSON.stringify(
    {
      policy_commitment: commitment,
      anchored_at: anchoredAt,
      metadata,
    },
    null,
    2
  );

  const res = await fetch(`https://api.github.com/gists/${gistId}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${githubToken}`,
      "Content-Type": "application/json",
      Accept: "application/vnd.github+json",
    },
    body: JSON.stringify({
      files: {
        [filename]: { content },
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to publish anchor: ${text}`);
  }

  return {
    anchor_url: `https://gist.github.com/${gistId}#file-${filename.replace(/\./g, "-")}`,
    anchored_at: anchoredAt,
  };
}
