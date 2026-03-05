import { create } from "zustand";
import type { Agent } from "./types";

interface AgentStore {
  agents: Agent[];
  setAgents: (agents: Agent[]) => void;
  lastFetchedAt: number | null;
  setLastFetchedAt: (ts: number | null) => void;
}

export const useAgentStore = create<AgentStore>((set) => ({
  agents: [],
  lastFetchedAt: null,
  setAgents: (agents) => set({ agents, lastFetchedAt: Date.now() }),
  setLastFetchedAt: (ts) => set({ lastFetchedAt: ts }),
}));
