"use client";

import { Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePolicyStore } from "@/lib/policy-store";
import { toast } from "sonner";

const POLICY_PLACEHOLDER = "YOUR_POLICY_COMMITMENT";
const PROXY_BASE = process.env.NEXT_PUBLIC_PROXY_URL ?? "http://127.0.0.1:8080";
const VERIFIER_BASE = process.env.NEXT_PUBLIC_VERIFIER_URL ?? "http://127.0.0.1:3000";

function CopyButton({ text }: { text: string }) {
  async function handleCopy() {
    await navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  }
  return (
    <Button variant="outline" size="icon" onClick={handleCopy}>
      <Copy className="h-4 w-4" />
    </Button>
  );
}

const pythonSnippet = (policyHash: string) => `from aegis_sdk import Aegis

# Force all outbound traffic through local Aegis Proxy
import os
os.environ["HTTP_PROXY"] = "${PROXY_BASE}"
os.environ["HTTPS_PROXY"] = "${PROXY_BASE}"

aegis = Aegis(
    base_url="${VERIFIER_BASE}",
    session_id="session-123",
    user_id="alice",
    iam_role="customer-support"
)

# Register policy then run your instrumented function calls
policy = {"public_values": {"max_spend": 1000, "restricted_endpoints": ["/admin"]}}
aegis.init(policy=policy, domain="defi", public_values=policy["public_values"])

@aegis.trace
def execute_swap(amount: float):
    return {"ok": True, "amount": amount}

execute_swap(500)
aegis.close()
`;

const curlSnippet = (_policyHash: string) => `# Sidecar receipt ingest endpoint (Control Plane)
curl -X POST http://localhost:3001/api/receipts \\
  -H "Content-Type: application/json" \\
  -H "X-Aegis-Ingest-Token: <optional-ingest-token>" \\
  -d '{
    "receipt_id":"5e195947-90a9-4f9a-a4d0-726f6147f5ec",
    "policy_commitment":"${POLICY_PLACEHOLDER}",
    "trace_hash":"0xabc123",
    "identity_hash":"0xdef456",
    "timestamp_ns":1738710021000000000,
    "signature":"<ed25519-signature-hex>",
    "public_key":"<ed25519-public-key-hex>"
  }'
`;

export default function SDKSandboxPage() {
  const policyCommitment = usePolicyStore((s) => s.policyCommitment);
  const hash = policyCommitment ?? POLICY_PLACEHOLDER;

  return (
    <div>
      <h1 className="text-2xl font-bold">SDK Sandbox</h1>
      <p className="mt-2 text-muted-foreground">
        Copy these snippets to integrate Aegis into your project. Replace the policy commitment
        with the hash from the Policy Builder.
      </p>

      {!policyCommitment && (
        <p className="mt-4 text-sm text-amber-500">
          No policy registered yet. Go to the Policy Builder to register a policy and get your
          commitment hash.
        </p>
      )}

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Code Snippets</CardTitle>
          <CardDescription>
            Python SDK and cURL examples. Replace {POLICY_PLACEHOLDER} with your policy_commitment
            if not yet set.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="python">
            <TabsList>
              <TabsTrigger value="python">Python</TabsTrigger>
              <TabsTrigger value="curl">cURL</TabsTrigger>
            </TabsList>
            <TabsContent value="python" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={pythonSnippet(hash)} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{pythonSnippet(hash)}</code>
              </pre>
            </TabsContent>
            <TabsContent value="curl" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={curlSnippet(hash)} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{curlSnippet(hash)}</code>
              </pre>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
