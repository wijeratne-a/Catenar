"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAgents, useSession } from "@/lib/api";

export default function AgentsPage() {
  const { data: agents, isLoading, isError } = useAgents();
  const session = useSession().data;
  const isAdmin = session?.role === "admin";

  if (!isAdmin) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Registered Agents</h1>
        <Card className="mt-8 border-amber-600/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant="outline" className="border-amber-600/50">
                Admin Only
              </Badge>
            </CardTitle>
            <CardDescription>
              You need the admin role to view registered agents. Agents register via POST
              /v1/agent/register on the verifier.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Registered Agents</h1>
        <p className="mt-2 text-muted-foreground">
          Agents that have registered with the verifier.
        </p>
        <Card className="mt-8">
          <CardHeader>
            <Skeleton className="h-6 w-48" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="mt-2 h-24 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isError) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Registered Agents</h1>
        <Card className="mt-8 border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant="destructive">Load Error</Badge>
            </CardTitle>
            <CardDescription>
              Failed to fetch agents. Ensure the verifier is running and VERIFIER_API_KEY is set.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const list = agents ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold">Registered Agents</h1>
      <p className="mt-2 text-muted-foreground">
        Agents that have registered with the verifier via POST /v1/agent/register.
      </p>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Agent Registry</CardTitle>
          <CardDescription>
            {list.length} agent{list.length !== 1 ? "s" : ""} (auto-refresh every 30s)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <p className="text-sm text-muted-foreground">No agents registered yet.</p>
          ) : (
            <div className="space-y-3">
              {list.map((a) => (
                <div
                  key={a.agent_id}
                  className="flex flex-wrap items-center gap-2 rounded-lg border border-border/50 bg-muted/20 p-3"
                >
                  <span className="font-mono font-medium">{a.agent_id}</span>
                  <Badge variant="secondary">{a.team}</Badge>
                  <Badge variant="outline">{a.model}</Badge>
                  <span className="text-xs text-muted-foreground">{a.env}</span>
                  <span className="text-xs text-muted-foreground">v{a.version}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
