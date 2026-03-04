import Link from "next/link";
import { Shield, Zap, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-border/40">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <span className="font-mono text-lg font-semibold">Aegis</span>
          <div className="flex gap-4">
            <Link href="/login">
              <Button variant="ghost">Log in</Button>
            </Link>
            <Link href="/login">
              <Button>Get Started</Button>
            </Link>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-16 md:py-24">
        <section className="mx-auto max-w-3xl text-center">
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl">
            Proof of Task for AI Agents
          </h1>
          <p className="mt-6 text-lg text-muted-foreground md:text-xl">
            Cryptographic verification that your AI agent executed exactly what it claimed.
            Build policies, trace execution, and receive tamper-proof receipts.
          </p>
          <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Link href="/login">
              <Button size="lg" className="w-full sm:w-auto">
                Launch Playground
              </Button>
            </Link>
            <Link href="/dashboard">
              <Button size="lg" variant="outline" className="w-full sm:w-auto">
                View Demo (Login Required)
              </Button>
            </Link>
          </div>
        </section>

        <section className="mt-24 grid gap-6 md:grid-cols-3">
          <Card>
            <CardHeader>
              <Shield className="h-10 w-10 text-primary" />
              <CardTitle>Policy Engine</CardTitle>
              <CardDescription>
                Define spend limits and restricted endpoints. Register policies and receive
                cryptographic commitments.
              </CardDescription>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader>
              <Zap className="h-10 w-10 text-primary" />
              <CardTitle>Cryptographic Proofs</CardTitle>
              <CardDescription>
                Every verification produces a signed PoT receipt with trace hash, timestamp,
                and Ed25519 signature.
              </CardDescription>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader>
              <Activity className="h-10 w-10 text-primary" />
              <CardTitle>Live Verification</CardTitle>
              <CardDescription>
                Submit execution traces and see results in real time. Success or security
                violation—instant feedback.
              </CardDescription>
            </CardHeader>
          </Card>
        </section>

        <section className="mt-24">
          <h2 className="mb-6 text-2xl font-bold">Quick Start</h2>
          <Card>
            <CardContent className="pt-6">
              <pre className="overflow-x-auto rounded-lg bg-muted/50 p-4 font-mono text-sm">
                <code>{`from aegis_sdk import Aegis

aegis = Aegis(base_url="https://your-verifier-host")
policy = {"public_values": {"max_spend": 1000, "restricted_endpoints": ["/admin"]}}
commitment = aegis.init(policy, domain="defi", public_values=policy["public_values"])

@aegis.trace
def execute_swap(amount: float):
    return {"txid": "0x..."}

execute_swap(500)   # Within limit
execute_swap(5000)  # Violation`}</code>
              </pre>
            </CardContent>
          </Card>
        </section>
      </main>

      <footer className="border-t border-border/40 py-8">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          Aegis Playground — Proof of Task verification for AI agents
        </div>
      </footer>
    </div>
  );
}
