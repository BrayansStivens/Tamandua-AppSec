import { useQuery } from '@tanstack/react-query'
import { craPolicyQuery } from '@/shared/api/queries'

// Audit evidence frameworks, shared by the audit report dialog (Findings) and the evidence hub (Compliance).
export type Framework = 'soc2' | 'iso27001' | 'pci' | 'cra' | 'br-cmn' | 'cl-21663' | 'co-sfc' | 'general'

// [id, name key, hint key]
export const FRAMEWORKS: [Framework, string, string][] = [
  ['soc2', 'audit.frameworks.soc2.name', 'audit.frameworks.soc2.hint'],
  ['iso27001', 'audit.frameworks.iso27001.name', 'audit.frameworks.iso27001.hint'],
  ['pci', 'audit.frameworks.pci.name', 'audit.frameworks.pci.hint'],
  ['cra', 'audit.frameworks.cra.name', 'audit.frameworks.cra.hint'],
  ['br-cmn', 'audit.frameworks.br_cmn.name', 'audit.frameworks.br_cmn.hint'],
  ['cl-21663', 'audit.frameworks.cl_21663.name', 'audit.frameworks.cl_21663.hint'],
  ['co-sfc', 'audit.frameworks.co_sfc.name', 'audit.frameworks.co_sfc.hint'],
  ['general', 'audit.frameworks.general.name', 'audit.frameworks.general.hint'],
]
const MEMORY = 'tamandua-audit-report'
// What doesn't change between reports is remembered in this browser (a convenience; nothing leaves it).
export const remembered = (): Partial<Record<string, string>> => { try { return JSON.parse(localStorage.getItem(MEMORY) ?? '{}') } catch { return {} } }
export const rememberedFramework = () => remembered().framework as Framework | undefined
export const rememberFramework = (framework: Framework) => { try { localStorage.setItem(MEMORY, JSON.stringify({ ...remembered(), framework })) } catch { /* no storage */ } }
// The CRA mapping only shows when the workspace sells products in the EU (policy in Policies).
export function useAuditFrameworks() {
  const policy = useQuery(craPolicyQuery())
  // While the policy loads nothing is hidden, so a remembered CRA choice isn't swapped for another framework.
  return policy.isPending ? FRAMEWORKS : FRAMEWORKS.filter(([id]) => id !== 'cra' || policy.data?.enabled === true)
}
export const rememberFrameworkDetails = (details: Record<string, string>) => { try { localStorage.setItem(MEMORY, JSON.stringify(details)) } catch { /* no storage */ } }
