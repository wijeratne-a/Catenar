import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type { RegisterPolicyInput } from "./schemas";
import type { PotReceipt, RegisterResponse } from "./types";

async function registerPolicy(payload: RegisterPolicyInput): Promise<RegisterResponse> {
  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "include",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export function useRegisterPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: registerPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

type ReceiptListResponse = {
  receipts: Array<{ received_at: string; value: PotReceipt }>;
};

export function useReceipts() {
  return useQuery({
    queryKey: ["receipts"],
    queryFn: async () => {
      const res = await fetch("/api/receipts", { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      const data = (await res.json()) as ReceiptListResponse;
      return data.receipts ?? [];
    },
    refetchInterval: 5000,
  });
}
