import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import type { SessionUser } from '@/features/auth/session'
import { EvidenceHub } from '@/features/compliance/evidence-hub'
import { CraSection } from '@/features/compliance/cra-section'
import { craPolicyQuery } from '@/shared/api/queries'

// Evidence for everyone; the CRA kit below it only when the workspace sells products in the EU (Policies).
export function Compliance({ user, onNew }: { user: SessionUser; onNew: () => void }) {
  const { t } = useTranslation('compliance')
  const policy = useQuery(craPolicyQuery())
  return <div className="space-y-6">
    <EvidenceHub onNew={onNew} />
    {/* Without the policy we can't know whether CRA deadlines apply: say so instead of hiding them silently. */}
    {policy.isError && <p role="alert" className="flex flex-wrap items-center gap-2 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">
      {t('cra.policy_failed')}<Button size="xs" variant="outline" onClick={() => void policy.refetch()}>{t('common:actions.retry')}</Button></p>}
    {policy.data?.enabled && <CraSection admin={user.role === 'admin'} onNew={onNew} />}
  </div>
}
