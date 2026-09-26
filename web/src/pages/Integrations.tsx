import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyRound } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { CodeSources } from '@/features/sources/code-sources'
import { JiraCard } from '@/features/integrations/jira'
import { RegistriesCard } from '@/features/sources/registries'
import { NotificationsCard } from '@/features/integrations/notifications'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { ComingSoonCard } from '@/shared/ui/coming-soon'
import { api } from '@/shared/api/http'

type ProviderStatus = { id: 'openai' | 'anthropic'; configured: boolean; env: string; owner: 'usuario' | 'servidor' | null; last4: string | null; saved_at: string | null }

// Proveedores de código, registros de contenedores, Jira y, en desarrollo, IA.
export function Integrations({ user }: { user: SessionUser }) {
  const { t } = useTranslation('integrations')
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<string | null>(null)
  const loadProviders = useCallback(() => api.get<ProviderStatus[]>('/api/providers').then(setProviders), [])
  useEffect(() => { loadProviders().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [loadProviders])
  const mine = providers.filter(provider => provider.owner === 'usuario')
  const removeKey = async (provider: ProviderStatus['id']) => {
    setBusy(provider); setError(null)
    try {
      const result = await api.post<{ providers?: ProviderStatus[] }>('/api/providers/keys', 'save-ai-key', { provider, action: 'remove' })
      if (result.providers) setProviders(result.providers); else await loadProviders()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy('') }
  }

  return <div className="space-y-5">
      {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
      {user.role !== 'admin' && <div className="rounded-xl border border-app-line bg-app-soft px-4 py-3 text-sm text-app-muted">{t('page.read_only')}</div>}
      <CodeSources canManage={user.role === 'admin'} />
      <RegistriesCard canManage={user.role === 'admin'} />
      {user.role === 'admin' && <NotificationsCard />}
      <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('page.issues_title')}</CardTitle><CardDescription>{t('page.issues_description')}</CardDescription></CardHeader><CardContent><JiraCard canManage={user.role === 'admin'} /></CardContent></Card>
      <ComingSoonCard title={t('page.ai.title')} icon={<KeyRound className="size-5" />}
        description={t('page.ai.description')}
        plan={[t('page.ai.plan.consent'), t('page.ai.plan.budget'), t('page.ai.plan.no_code')]}>
        {mine.length > 0 && <div className="mt-4 space-y-2">{mine.map(provider => <div key={provider.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-app-line px-3 py-2 text-xs">
          <span>{t('page.ai.saved_key', { provider: provider.id === 'openai' ? 'OpenAI' : 'Anthropic', last4: provider.last4 ?? '' })}</span>
          {user.role === 'admin' && <Button size="xs" variant="ghost" disabled={!!busy} onClick={() => void removeKey(provider.id)}>{t('page.ai.remove_key')}</Button>}
        </div>)}</div>}
      </ComingSoonCard>
    </div>
}
