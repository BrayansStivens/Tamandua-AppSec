import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/shared/api/http'
import { Globe2, LoaderCircle, Plus, Search, ShieldCheck } from 'lucide-react'
import { AddDomainDialog, VerifyDomainDialog, kindLabel, type Domain } from '@/features/sources/domain-dialogs'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'

export function DomainAssets({ onConfigure }: { onConfigure: () => void }) {
  const { t } = useTranslation('sources')
  const [domains, setDomains] = useState<Domain[]>([])
  const [filter, setFilter] = useState('')
  const [adding, setAdding] = useState(false)
  const [pending, setPending] = useState<Domain | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { api.get<Domain[]>('/api/domains').then(setDomains).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [])
  const upsert = (domain: Domain) => setDomains(previous => [...previous.filter(item => item.id !== domain.id), domain])
  const verify = async (id: string) => {
    setBusy(id); setError('')
    try {
      upsert(await api.post<Domain>('/api/domains/verify', 'verify-domain', { domain_id: id }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy('') }
  }
  const visible = domains.filter(domain => domain.host.includes(filter.trim().toLowerCase()))

  return <div className="space-y-5">
    <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('domains.list.title')}</CardTitle><CardDescription>{t('domains.list.description')}</CardDescription></div><Button onClick={() => setAdding(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus /> {t('domains.add.title')}</Button></CardHeader>
      <CardContent className="space-y-5">
        <div className="relative max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('domains.list.search')} placeholder={t('domains.list.search_placeholder')} value={filter} onChange={event => setFilter(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
        <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[minmax(0,1fr)_150px_150px_130px] gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid"><span>{t('domains.list.columns.domain')}</span><span>{t('domains.list.columns.kind')}</span><span>{t('domains.list.columns.verification')}</span><span>{t('domains.list.columns.last_test')}</span></div>
          {visible.map(domain => <div key={domain.id} className="border-b border-app-line p-4 last:border-b-0">
            <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_150px_150px_130px] md:items-center">
              <div className="flex min-w-0 items-center gap-2"><Globe2 className="size-4 shrink-0 text-app-muted" /><span className="truncate font-mono text-sm">{domain.host}</span></div>
              <span className="text-xs text-app-muted">{kindLabel[domain.kind ?? 'web']}</span>
              <Badge variant="outline" className={`w-fit ${domain.verified ? 'border-brand/30 text-brand' : 'border-warning-line text-warning'}`}>{domain.verified ? t('domains.list.verified') : t('domains.list.unverified')}</Badge>
              <span className="text-xs text-app-muted">{t('domains.list.not_tested')}</span>
            </div>
            {domain.context && <p className="mt-3 text-xs leading-5 text-app-subtle">{domain.context}</p>}
            {!domain.verified && <div className="mt-3 flex flex-wrap items-center gap-3"><Button variant="outline" size="sm" disabled={!!busy} onClick={() => void verify(domain.id)} className="border-app-line bg-app-soft">{busy === domain.id ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />} {t('domains.list.verify_dns')}</Button><Button variant="ghost" size="sm" onClick={() => setPending(domain)}>{t('domains.list.show_txt')}</Button></div>}
          </div>)}
          {!visible.length && <p className="p-10 text-center text-sm text-app-muted">{domains.length ? t('domains.list.no_match') : t('domains.list.empty')}</p>}
          {domains.length > 0 && <div className="px-4 py-3 text-xs text-app-subtle">{t('domains.list.showing', { visible: visible.length, count: domains.length })}</div>}
        </div>
        <Button variant="outline" onClick={onConfigure} className="border-app-line bg-app-soft">{t('domains.list.configure')}</Button>
      </CardContent>
    </Card>
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error}</div>}
    <AddDomainDialog open={adding} onOpenChange={setAdding} onAdded={domain => { upsert(domain); setPending(domain) }} />
    <VerifyDomainDialog domain={pending} onOpenChange={() => setPending(null)} onVerified={domain => { upsert(domain); setPending(null) }} />
  </div>
}
