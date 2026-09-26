import { useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import { SlaPolicyRow } from '@/features/policies/sla-policy'
import { SecretDefaultsRow } from '@/features/policies/secret-defaults'
import { Card, CardContent } from '@/shared/ui/card'

// Settings that apply to every repository. A repository's own settings (excluded paths, extra secret entries) are
// on its Findings page.
export function Policies({ user }: { user: SessionUser }) {
  const { t } = useTranslation('policies')
  const admin = user.role === 'admin'
  return <div className="max-w-4xl space-y-4">
    <Card className="border-app-line bg-panel"><CardContent className="divide-y divide-app-line p-0">
      <SlaPolicyRow canEdit={admin} />
      <SecretDefaultsRow canEdit={admin} />
    </CardContent></Card>
    <details className="rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
      <summary className="min-h-6 cursor-pointer font-medium text-app-secondary">{t('help.title')}</summary>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-app-muted">
        <li>{t('help.sla')}</li>
        <li>{t('help.secrets')}</li>
        <li>{t('help.repository')}</li>
        <li>{t('help.critical')}</li>
        {!admin && <li>{t('help.admin_only')}</li>}
      </ul>
    </details>
  </div>
}
