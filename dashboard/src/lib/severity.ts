export enum ViolationSeverity {
  Critical = "critical",
  High = "high",
  Medium = "medium",
  Low = "low",
}

const SEVERITY_ORDER: Record<ViolationSeverity, number> = {
  [ViolationSeverity.Low]: 1,
  [ViolationSeverity.Medium]: 2,
  [ViolationSeverity.High]: 3,
  [ViolationSeverity.Critical]: 4,
};

export function severityRank(severity: ViolationSeverity): number {
  return SEVERITY_ORDER[severity];
}

export function classifyViolation(reason: string, violation_type?: string): ViolationSeverity {
  const source = `${violation_type ?? ""} ${reason}`.toLowerCase();

  if (
    source.includes("sensitive_data_exposure") ||
    source.includes("sensitive data exposure") ||
    source.includes("ssn") ||
    source.includes("sensitive")
  ) {
    return ViolationSeverity.Critical;
  }

  if (
    source.includes("response_injection") ||
    source.includes("response injection") ||
    source.includes("responseinjection")
  ) {
    return ViolationSeverity.High;
  }

  if (
    source.includes("missing_audit_trace") ||
    source.includes("missing audit trace") ||
    source.includes("x-catenar-trace") ||
    source.includes("audit")
  ) {
    return ViolationSeverity.Medium;
  }

  if (source.includes("schema")) {
    return ViolationSeverity.Medium;
  }

  if (
    source.includes("unauthorized_data_mutation") ||
    source.includes("unauthorized data mutation") ||
    source.includes("readonly") ||
    source.includes("read-only") ||
    source.includes("delete mutation")
  ) {
    return ViolationSeverity.High;
  }

  if (source.includes("policy_violation") || source.includes("policy violation")) {
    return ViolationSeverity.Medium;
  }

  return ViolationSeverity.Low;
}

export function severityColor(severity: ViolationSeverity): string {
  switch (severity) {
    case ViolationSeverity.Critical:
      return "bg-red-600/15 text-red-700 border border-red-600/30";
    case ViolationSeverity.High:
      return "bg-orange-600/15 text-orange-700 border border-orange-600/30";
    case ViolationSeverity.Medium:
      return "bg-amber-600/15 text-amber-700 border border-amber-600/30";
    case ViolationSeverity.Low:
    default:
      return "bg-slate-600/15 text-slate-700 border border-slate-600/30";
  }
}
