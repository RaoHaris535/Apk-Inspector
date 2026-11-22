export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string[];
  remediation: string;
  score: number;
}

export interface ComponentInfo { name: string; exported: boolean | null }
export interface Certificate {
  sha256: string;
  sha1: string;
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  valid_from: string | null;
  valid_until: string | null;
}

export interface AnalysisReport {
  analysis_id: string;
  status: "complete";
  filename: string;
  size_bytes: number;
  sha256: string;
  received_at: string;
  archive: {
    entry_count: number;
    compressed_bytes: number;
    uncompressed_bytes: number;
    dex_files: number;
    native_libraries: number;
  };
  metadata: {
    package_name: string;
    app_name: string;
    version_name: string | null;
    version_code: string | null;
    main_activity: string | null;
    sdk: { minimum: number | null; target: number | null; maximum: number | null };
    permissions: string[];
    declared_permissions: string[];
    components: {
      activities: ComponentInfo[];
      services: ComponentInfo[];
      receivers: ComponentInfo[];
      providers: ComponentInfo[];
    };
    libraries: string[];
    signing: {
      signed_v1: boolean;
      signed_v2: boolean;
      signed_v3: boolean;
      certificates: Certificate[];
    };
  };
  code: {
    urls: string[];
    cleartext_urls: string[];
    secrets: Array<{ kind: string; evidence: string; source: string }>;
    techniques: Array<{ technique: string; evidence: string[] }>;
    native_libraries: Array<{ path: string; architecture: string; size_bytes: number }>;
    scanned_files: number;
  };
  findings: Finding[];
  risk: {
    score: number;
    rating: "low" | "moderate" | "high" | "critical";
    finding_count: number;
    severity_counts: Record<Severity, number>;
  };
}

export interface ComparisonReport {
  comparison_id: string;
  status: "complete";
  submitted: AnalysisReport;
  reference: AnalysisReport;
  differences: {
    identical_file: boolean;
    package_name_matches: boolean;
    signing_certificate_matches: boolean;
    added_permissions: string[];
    removed_permissions: string[];
    added_components: string[];
    removed_components: string[];
    added_urls: string[];
    removed_urls: string[];
    added_native_libraries: string[];
    removed_native_libraries: string[];
    risk_score_delta: number;
  };
  possible_repackaging: boolean;
}

export function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function componentCount(report: AnalysisReport) {
  const components = report.metadata.components;
  return components.activities.length + components.services.length + components.receivers.length + components.providers.length;
}
