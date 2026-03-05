"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { FileCode, FileSpreadsheet, Shield, Terminal, AlertTriangle, Users, Plug } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard/policy", label: "Policy Builder", icon: Shield },
  { href: "/dashboard/receipts", label: "Receipts", icon: FileCode },
  { href: "/dashboard/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/dashboard/agents", label: "Agents", icon: Users },
  { href: "/dashboard/compliance", label: "Compliance", icon: FileSpreadsheet },
  { href: "/dashboard/integrations", label: "Integrations", icon: Plug },
];

export function DashboardSidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-full shrink-0 flex-col border-b border-r-0 border-border/40 bg-card/50 md:w-56 md:border-b-0 md:border-r">
      <div className="p-4">
        <Link href="/dashboard" className="font-mono font-semibold">
          Aegis Playground
        </Link>
      </div>
      <nav className="flex flex-1 flex-row gap-2 overflow-x-auto px-2 py-2 md:flex-col md:space-y-1 md:overflow-x-visible md:py-0">
        {navItems.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex shrink-0 items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors md:shrink",
              pathname === href
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
            )}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className="whitespace-nowrap">{label}</span>
          </Link>
        ))}
      </nav>
    </aside>
  );
}
