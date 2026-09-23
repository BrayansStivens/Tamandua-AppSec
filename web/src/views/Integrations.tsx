import { useCallback, useEffect, useState } from 'react'
import { ExternalLink, KeyRound, PlugZap, RefreshCw } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { CodeSources } from '@/components/code-sources'
import { JiraCard } from '@/components/jira'
import { RegistriesCard } from '@/components/registries'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { formatDate as isoDate } from '@/lib/types'

type ProviderStatus = { id: 'openai' | 'anthropic'; configured: boolean; env: string; owner: 'usuario' | 'servidor' | null; last4: string | null; saved_at: string | null }
type ProviderCheck = { provider: string; status: string; message: string; models_visible?: number }
const providerStatusText = (status: string) => ({ connected: 'Conectado', not_configured: 'Sin configurar', invalid_credentials: 'Credencial rechazada', rate_limited: 'Límite del proveedor', unreachable: 'No disponible', error: 'Error de comprobación' }[status] ?? 'Estado desconocido')

// Proveedores de código y claves de IA propias del usuario (BYOK).
export function Integrations({ user }: { user: SessionUser }) {
  const [providers, setProviders] = useState<ProviderStatus[]>([])
  const [providerChecks, setProviderChecks] = useState<Record<string, ProviderCheck>>({})
  const [checkingProvider, setCheckingProvider] = useState<string | null>(null)
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({})
  const [error, setError] = useState<string | null>(null)
  const loadProviders = useCallback(() => api.get<ProviderStatus[]>('/api/providers').then(setProviders), [])
  useEffect(() => { loadProviders().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [loadProviders])

  const saveKey = async (provider: ProviderStatus['id'], action: 'save' | 'remove', apiKey?: string) => {
    setCheckingProvider(provider)
    setError(null)
    try {
      const result = await api.post<{ providers?: ProviderStatus[]; result?: ProviderCheck }>('/api/providers/keys', 'save-ai-key',
        action === 'save' ? { provider, action, api_key: apiKey } : { provider, action })
      if (result.providers) setProviders(result.providers)
      if (result.result) setProviderChecks(previous => ({ ...previous, [provider]: result.result! }))
      setApiKeys(previous => ({ ...previous, [provider]: '' }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setCheckingProvider(null) }
  }
  const checkProvider = async (provider: ProviderStatus['id']) => {
    setCheckingProvider(provider)
    setError(null)
    try {
      const result = await api.post<ProviderCheck>('/api/providers/check', 'check-provider', { provider })
      setProviderChecks(previous => ({ ...previous, [provider]: result }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setCheckingProvider(null) }
  }

  return <div className="space-y-5">
      {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
      {user.role !== 'admin' && <div className="rounded-xl border border-app-line bg-app-soft px-4 py-3 text-sm text-app-muted">Conectar proveedores y guardar claves es cosa de un administrador; aquí ves su estado.</div>}
      <CodeSources canManage={user.role === 'admin'} />
      <RegistriesCard canManage={user.role === 'admin'} />
      <Card className="border-app-line bg-panel"><CardHeader><CardTitle>Gestión de incidencias</CardTitle><CardDescription>Convierte hallazgos pendientes en incidencias de tu equipo, sin duplicados entre escaneos.</CardDescription></CardHeader><CardContent><JiraCard canManage={user.role === 'admin'} /></CardContent></Card>
      <Card className="border-app-line bg-panel"><CardHeader><CardTitle>Asistencia con IA</CardTitle><CardDescription>Usa tu propia clave de API: el consumo se factura a tu cuenta y puedes retirarla cuando quieras. La clave se queda en este servidor y nunca vuelve al navegador.</CardDescription></CardHeader><CardContent className="grid gap-4 lg:grid-cols-2">{(['openai', 'anthropic'] as const).map(id => {
        const provider = providers.find(item => item.id === id)
        const result = providerChecks[id]
        const name = id === 'openai' ? 'OpenAI · GPT' : 'Anthropic · Claude'
        const mine = provider?.owner === 'usuario'
        return <div key={id} className="rounded-xl border border-app-line bg-inset p-5"><div className="flex items-start justify-between gap-3"><div className="flex items-center gap-3"><div className="rounded-xl bg-brand/10 p-2 text-brand"><KeyRound className="size-5" /></div><div><h3 className="font-semibold">{name}</h3><p className="text-xs text-app-subtle">{mine ? `Tu clave · ····${provider?.last4}` : provider?.owner === 'servidor' ? 'Clave del servicio' : 'Sin clave'}</p></div></div><Badge variant="outline" className={provider?.configured ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{provider?.configured ? 'Activa' : 'Sin configurar'}</Badge></div>
          {mine ? <div className="mt-5 space-y-3"><p className="text-sm leading-6 text-app-muted">{provider?.saved_at ? `Guardada el ${isoDate(provider.saved_at)} y validada contra el proveedor.` : 'Guardada y validada.'}</p><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => checkProvider(id)} disabled={!!checkingProvider} className="border-app-line bg-app-soft">{checkingProvider === id ? <RefreshCw className="animate-spin" /> : <PlugZap />}Volver a probar</Button><Button variant="ghost" disabled={!!checkingProvider} onClick={() => void saveKey(id, 'remove')}>Retirar clave</Button></div></div>
          : <form className="mt-5 space-y-3" onSubmit={event => { event.preventDefault(); void saveKey(id, 'save', apiKeys[id] ?? '') }}>
            <label className="block text-xs text-app-muted" htmlFor={`ai-key-${id}`}>Clave de API de {id === 'openai' ? 'OpenAI' : 'Anthropic'}</label>
            <Input id={`ai-key-${id}`} type="password" autoComplete="new-password" required minLength={20} maxLength={400} value={apiKeys[id] ?? ''} onChange={event => setApiKeys(previous => ({ ...previous, [id]: event.target.value }))} placeholder={id === 'openai' ? 'sk-…' : 'sk-ant-…'} className="border-app-line bg-app-soft" />
            <Button type="submit" disabled={!!checkingProvider || (apiKeys[id] ?? '').length < 20} className="bg-primary text-primary-foreground hover:bg-primary/90">{checkingProvider === id ? <RefreshCw className="animate-spin" /> : <PlugZap />}Guardar y validar</Button>
            <p className="text-xs leading-5 text-app-subtle">Se comprueba contra el proveedor antes de guardarla: si la rechaza, no se guarda.</p>
            <a href={id === 'openai' ? 'https://platform.openai.com/api-keys' : 'https://platform.claude.com/settings/keys'} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand hover:underline">Crear una clave en {id === 'openai' ? 'OpenAI' : 'Anthropic'} <ExternalLink className="size-3" /></a>
          </form>}
          {result && <div role="status" className={`mt-3 text-xs ${result.status === 'connected' ? 'text-brand' : 'text-amber-700 dark:text-amber-300'}`}>Estado: {providerStatusText(result.status)}{result.models_visible !== undefined ? ` · ${result.models_visible} modelos visibles` : ''}</div>}
        </div>
      })}</CardContent></Card>
      <Card className="border-amber-500/20 bg-amber-500/5"><CardContent className="space-y-2 pt-6 text-sm text-amber-950 dark:text-amber-100/80"><p><strong className="font-medium">Guardar la clave todavía no cambia ningún análisis.</strong> Hoy los resultados son deterministas y no se llama a ningún modelo. Cuando la asistencia con IA se habilite, pedirá tu consentimiento en cada ejecución antes de enviar nada, con presupuesto por ejecución y redacción de secretos.</p><p>No se envía código fuente a ningún proveedor sin ese consentimiento explícito.</p></CardContent></Card>
    </div>
}
