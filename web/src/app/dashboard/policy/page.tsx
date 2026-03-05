"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Copy, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useRegisterPolicy } from "@/lib/api";
import { usePolicyStore } from "@/lib/policy-store";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const policyFormSchema = z.object({
  domain: z.enum(["defi", "enterprise"]),
  max_spend: z.union([z.coerce.number().positive(), z.literal("")]).optional(),
  restricted_endpoints: z.array(z.string()),
  rego_policy: z.string().optional(),
});

type PolicyForm = z.infer<typeof policyFormSchema>;

export default function PolicyBuilderPage() {
  const { policyCommitment, setPolicyCommitment } = usePolicyStore();
  const registerMutation = useRegisterPolicy();
  const anchorUrl = registerMutation.data?.anchor_url;
  const anchoredAt = registerMutation.data?.anchored_at;

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<PolicyForm>({
    resolver: zodResolver(policyFormSchema),
    defaultValues: {
      domain: "defi",
      max_spend: "" as unknown as number | undefined,
      restricted_endpoints: [""],
      rego_policy: "package aegis\n\ndefault allow = false\ndefault reason = \"policy denied request\"\n",
    },
  });

  const restrictedEndpoints = watch("restricted_endpoints");

  function addEndpoint() {
    setValue("restricted_endpoints", [...restrictedEndpoints, ""]);
  }

  function removeEndpoint(idx: number) {
    const next = restrictedEndpoints.filter((_, i) => i !== idx);
    setValue("restricted_endpoints", next.length > 0 ? next : [""]);
  }

  async function onSubmit(data: PolicyForm) {
    const payload = {
      public_values: {
        max_spend: data.domain === "defi" && data.max_spend ? Number(data.max_spend) : undefined,
        restricted_endpoints:
          data.restricted_endpoints.filter(Boolean).length > 0
            ? data.restricted_endpoints.filter(Boolean)
            : undefined,
      },
      rego_policy: data.rego_policy?.trim() ? data.rego_policy : undefined,
    };

    try {
      const result = await registerMutation.mutateAsync(payload);
      setPolicyCommitment(result.policy_commitment);
      toast.success("Policy registered successfully");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Registration failed");
    }
  }

  async function copyHash() {
    if (!policyCommitment) return;
    await navigator.clipboard.writeText(policyCommitment);
    toast.success("Copied to clipboard");
  }

  return (
    <div>
      <h1 className="text-2xl font-bold">Policy Builder</h1>
      <p className="mt-2 text-muted-foreground">
        Configure max_spend and restricted_endpoints. Submit to get a policy commitment hash.
      </p>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Register Policy</CardTitle>
          <CardDescription>Values will be hashed to produce a BLAKE3 commitment.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div className="space-y-2">
              <Label>Domain</Label>
              <div className="flex gap-4">
                {(["defi", "enterprise"] as const).map((d) => (
                  <label key={d} className="flex items-center gap-2">
                    <input
                      type="radio"
                      value={d}
                      {...register("domain")}
                      className="rounded border-input"
                    />
                    <span className="capitalize">{d}</span>
                  </label>
                ))}
              </div>
            </div>

            <Tabs defaultValue="json" className="space-y-3">
              <TabsList>
                <TabsTrigger value="json">JSON Constraints</TabsTrigger>
                <TabsTrigger value="rego">Rego Policy</TabsTrigger>
              </TabsList>
              <TabsContent value="json" className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="max_spend">Max Spend (DeFi only)</Label>
                  <Input
                    id="max_spend"
                    type="number"
                    step="0.01"
                    placeholder="1000"
                    {...register("max_spend")}
                  />
                  {errors.max_spend && (
                    <p className="text-sm text-destructive">{errors.max_spend.message}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>Restricted Endpoints / Tables</Label>
                    <Button type="button" variant="ghost" size="sm" onClick={addEndpoint}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="space-y-2">
                    {restrictedEndpoints.map((_, idx) => (
                      <div key={idx} className="flex gap-2">
                        <Input
                          placeholder={watch("domain") === "defi" ? "/admin" : "salary"}
                          {...register(`restricted_endpoints.${idx}`)}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => removeEndpoint(idx)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="rego" className="space-y-2">
                <Label htmlFor="rego_policy">Rego Policy Source (optional)</Label>
                <textarea
                  id="rego_policy"
                  rows={12}
                  className="w-full rounded-md border border-input bg-background p-3 font-mono text-sm"
                  placeholder="package aegis"
                  {...register("rego_policy")}
                />
              </TabsContent>
            </Tabs>

            <Button type="submit" disabled={registerMutation.isPending}>
              {registerMutation.isPending ? "Registering..." : "Register Policy"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {policyCommitment && (
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>Policy Commitment</CardTitle>
            <CardDescription>Use this hash when verifying traces.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded bg-muted/50 px-3 py-2 font-mono text-sm">
                {policyCommitment}
              </code>
              <Button variant="outline" size="icon" onClick={copyHash}>
                <Copy className="h-4 w-4" />
              </Button>
            </div>
            {anchorUrl && (
              <div className="mt-4 space-y-1 text-sm">
                <p className="text-muted-foreground">Public Anchor</p>
                <a
                  href={anchorUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-primary underline"
                >
                  {anchorUrl}
                </a>
                {anchoredAt && (
                  <p className="text-xs text-muted-foreground">anchored_at: {anchoredAt}</p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
