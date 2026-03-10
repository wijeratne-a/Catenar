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

const pythonSnippet = (policyHash: string) => `# Env: HTTP_PROXY=${PROXY_BASE} HTTPS_PROXY=${PROXY_BASE}
# NO_PROXY=127.0.0.1,localhost  REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt

from catenar_sdk import Catenar

catenar = Catenar(base_url="${VERIFIER_BASE}", session_id="session-123", user_id="alice")
policy = {"public_values": {"max_spend": 1000, "restricted_endpoints": ["/admin"]}}
catenar.init(policy=policy, domain="defi", public_values=policy["public_values"])

@catenar.trace
def execute_swap(amount: float):
    return {"ok": True, "amount": amount}

execute_swap(500)
catenar.close()
`;

const pythonHttpxSnippet = `# Auto-trace HTTP with catenar_intercept (no decorators)
# pip install httpx catenar-sdk

import catenar_intercept  # MUST import before httpx
from catenar_intercept import get_catenar
import httpx

catenar = get_catenar()
catenar.init(policy={"public_values": {"restricted_endpoints": ["/admin"]}}, domain="defi", public_values={"restricted_endpoints": ["/admin"]})

resp = httpx.get("https://api.example.com/data")  # Auto-traced via proxy
catenar.wait_for_results(1)
catenar.close()
`;

const nodeSnippet = `// Env: HTTP_PROXY=${PROXY_BASE} HTTPS_PROXY=${PROXY_BASE}
// NODE_EXTRA_CA_CERTS=./deploy/certs/ca.crt

const { Catenar } = require("catenar-sdk");

(async () => {
  const catenar = new Catenar({ baseUrl: "${VERIFIER_BASE}" });
  const policy = { public_values: { max_spend: 1000, restricted_endpoints: ["/admin"] } };
  await catenar.init(policy, "defi", policy.public_values);

  catenar.trace("execute_swap", "/api/swap", { amount: 500 });
  const res = await catenar.verify();
  console.log(res);
})();
`;

const webhookConfig = `# Verifier: send policy violations to Control Plane
WEBHOOK_URL=https://your-control-plane.example.com/api/alerts/ingest
WEBHOOK_SECRET=<min-32-chars-secret-shared-with-control-plane>
`;

const curlIngest = `# Sidecar receipt ingest (Control Plane)
curl -X POST https://your-control-plane.example.com/api/receipts \\
  -H "Content-Type: application/json" \\
  -H "X-Catenar-Ingest-Token: <SIDECAR_INGEST_TOKEN>" \\
  -d '{"receipt_id":"...","policy_commitment":"...","trace_hash":"...","timestamp_ns":0,"signature":"...","public_key":"..."}'
`;

export default function IntegrationsPage() {
  const policyCommitment = usePolicyStore((s) => s.policyCommitment);
  const hash = policyCommitment ?? POLICY_PLACEHOLDER;

  return (
    <div>
      <h1 className="text-2xl font-bold">Integrations</h1>
      <p className="mt-2 text-muted-foreground">
        SDK snippets, webhook configuration, and API examples for connecting Catenar to your stack.
      </p>

      {!policyCommitment && (
        <p className="mt-4 text-sm text-amber-500">
          No policy registered yet. Go to the Policy Builder to register a policy and get your
          commitment hash.
        </p>
      )}

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Code & Configuration</CardTitle>
          <CardDescription>
            Python SDK, webhook config, and cURL examples.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="python">
            <TabsList className="flex-wrap">
              <TabsTrigger value="python">Python</TabsTrigger>
              <TabsTrigger value="python-httpx">Python httpx</TabsTrigger>
              <TabsTrigger value="node">Node.js</TabsTrigger>
              <TabsTrigger value="webhook">Webhook Config</TabsTrigger>
              <TabsTrigger value="curl">cURL Ingest</TabsTrigger>
            </TabsList>
            <TabsContent value="python" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={pythonSnippet(hash)} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{pythonSnippet(hash)}</code>
              </pre>
              <p className="mt-2 text-sm text-muted-foreground">
                Set HTTP_PROXY, HTTPS_PROXY, NO_PROXY, REQUESTS_CA_BUNDLE. Register policy, trace calls, verify.
              </p>
            </TabsContent>
            <TabsContent value="python-httpx" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={pythonHttpxSnippet} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{pythonHttpxSnippet}</code>
              </pre>
              <p className="mt-2 text-sm text-muted-foreground">
                Import catenar_intercept before httpx to auto-trace all HTTP calls through the proxy.
              </p>
            </TabsContent>
            <TabsContent value="node" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={nodeSnippet} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{nodeSnippet}</code>
              </pre>
              <p className="mt-2 text-sm text-muted-foreground">
                Set HTTP_PROXY, HTTPS_PROXY, NODE_EXTRA_CA_CERTS. Use catenar.trace for custom actions.
              </p>
            </TabsContent>
            <TabsContent value="webhook" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={webhookConfig} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{webhookConfig}</code>
              </pre>
              <p className="mt-2 text-sm text-muted-foreground">
                Set these in the verifier environment. The control plane must have the same
                WEBHOOK_SECRET to validate incoming alerts.
              </p>
            </TabsContent>
            <TabsContent value="curl" className="mt-4">
              <div className="flex justify-end">
                <CopyButton text={curlIngest} />
              </div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{curlIngest}</code>
              </pre>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
