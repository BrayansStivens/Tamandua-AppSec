// Formas de las ejecuciones tal como las sirve /api/runs/{id}.
import type { ProgressEvent } from '@/components/run-progress'

export type Summary = { planned?: number; executed?: number; confirmed?: number; needs_follow_up?: number; passed?: number; total?: number }
export type RunRow = { id: string; type: string; status: string; created_at: string; fixture: string; variant?: string; source?: { name: string; provider: string; sha256: string; files: number }; summary: Summary & { files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; severities?: Record<string, number>; kev?: number } }
export type Observation = { status: number; tenant?: string | null; role?: string | null; json_keys: string[]; document_tenants: string[] }
export type Attempt = { phase: string; observations: Observation[] }
export type Finding = { finding_id: string; rule_id: string; title: string; severity: string; confidence: number; endpoint: string; impact: string; cwe: number[]; cve?: string[]; ghsa?: string[]; owasp: string[]; reproduction_steps: { method: string; path: string; token: string; json?: Record<string, string> }[]; evidence: Attempt[] }
export type Coverage = { probe_id: string; endpoint: string; status: string; reason?: string; attempts: Attempt[] }
export type OwaspCoverage = { id: string; title: string; status: 'partial' | 'not_tested' | 'inconclusive'; probe_ids: string[]; reason: string }
export type RepositoryFinding = { finding_id: string; scanner: string; rule_id: string; title: string; path: string; line: number; severity: string; confidence: number; verdict: string; cwe: number[]; cve: string[]; ghsa: string[]; owasp: string[]; reason: string; remediation: string }
export type ScanStep = { id: string; name: string; status: string; detail: string }
export type RunDetail = RunRow & { findings?: Finding[] | RepositoryFinding[]; coverage?: Coverage[]; owasp_coverage?: OwaspCoverage[]; steps?: ScanStep[]; progress?: ProgressEvent[]; started_at?: string; finished_at?: string }
