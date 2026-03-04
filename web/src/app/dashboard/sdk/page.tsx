"use client";

import { Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePolicyStore } from "@/lib/policy-store";
import { toast } from "sonner";

const POLICY_PLACEHOLDER = "YOUR_POLICY_COMMITMENT";
const API_BASE = process.env.NEXT_PUBLIC_VERIFIER_URL ?? "http://127.0.0.1:3000";

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

const pythonSnippet = (policyHash: string) => `from aegis_sdk import Aegis, AegisClient

# Initialize with your policy commitment from the Policy Builder
client = AegisClient(base_url="${API_BASE}")

policy = {
    "public_values": {
        "max_spend": 1000,
        "restricted_endpoints": ["/admin"]
    }
}
commitment = client.register_policy(policy)
print(f"Policy commitment: {commitment}")

# Verify a trace
payload = {
    "agent_metadata": {"domain": "defi", "version": "1.0"},
    "policy_commitment": "${policyHash}",
    "execution_trace": [
        {"action": "api_call", "target": "https://dex.api/swap", "amount": 500}
    ],
    "public_values": {
        "max_spend": 1000,
        "restricted_endpoints": ["/admin"]
    }
}
result = client.verify(payload)
print(result.response_body)
`;

const curlSnippet = (policyHash: string) => `# Register a policy
curl -X POST ${API_BASE}/v1/register \\
  -H "Content-Type: application/json" \\
  -d '{"public_values":{"max_spend":1000,"restricted_endpoints":["/admin"]}}'

# Verify a trace (use your policy_commitment from above)
curl -X POST ${API_BASE}/v1/verify \\
  -H "Content-Type: application/json" \\
  -d '{
    "agent_metadata": {"domain": "defi", "version": "1.0"},
    "policy_commitment": "${policyHash}",
    "execution_trace": [
      {"action": "api_call", "target": "https://dex.api/swap", "amount": 500}
    ],
    "public_values": {
      "max_spend": 1000,
      "restricted_endpoints": ["/admin"]
    }
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
