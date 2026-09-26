import { useCallback, useState, type ReactNode, useId } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowDownToLine, LoaderCircle } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { SkeletonCard } from '@/shared/ui/loading'
import { api, query } from '@/shared/api/http'
import type { Response } from '@/shared/api/client'
import { evidenceAssetsQuery, evidenceQuery } from '@/shared/api/queries'
import { remembered, rememberFramework, rememberedFramework, useAuditFrameworks, type Framework } from '@/features/findings/audit-frameworks'

type Asset = Response<'/api/evidence/assets'>['items'][number]
type Item = 'sbom' | 'vex' | 'technical' | 'audit' | 'portfolio' | 'portfolio_sbom' | 'portfolio_vex'
const slug = (name: string, fallback: string) => name.replace(/[^a-z0-9-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 50) || fallback

// Evidence hub: the files auditors and customers ask for, per asset and for the whole portfolio. Every file is built on
// the server; the per-asset ones are the same exports as in Findings.
export function EvidenceHub({ onNew }: { onNew: () => void }) {
  const { t } = useTranslation('compliance')
  const { t: tf } = useTranslation('findings')
  const queryClient = useQueryClient()
  const overview = useQuery(evidenceQuery())
  const frameworks = useAuditFrameworks()
  const [chosen, setChosen] = useState<Framework>(() => rememberedFramework() ?? 'soc2')
  const framework: Framework = frameworks.some(([id]) => id === chosen) ? chosen : 'soc2'
  const current = frameworks.find(([id]) => id === framework)
  const frameworkName = current ? tf(current[1]) : framework
  const [picked, setPicked] = useState<(ComboOption & { asset: Asset }) | null>(null)
  const [busy, setBusy] = useState<Item | null>(null)
  const [error, setError] = useState('')

  const search = useCallback((q: string) => queryClient.fetchQuery(evidenceAssetsQuery(q)).then(page => ({
    options: page.items.map(asset => ({ id: asset.key, label: asset.name, hint: asset.kind === 'image' ? t('evidence.image') : t('evidence.repository'), asset })),
    total: page.total })), [queryClient, t])
  const download = async (item: Item, run: () => Promise<void>) => {
    if (busy) return
    setBusy(item); setError('')
    try { await run() } catch (caught) { setError(t('evidence.failed', { error: caught instanceof Error ? caught.message : String(caught) })) } finally { setBusy(null) }
  }
  const exportFile = (item: Item, asset: Asset, artifact: string, status: 'open' | 'all') => download(item, () =>
    api.download(`/api/assets/export?${query({ key: asset.key, status, artifact })}`, `${slug(asset.name, t('evidence.file_asset'))}-${artifact}`))
  const portfolioFile = (item: Item, url: string, suffix: string) => download(item, () =>
    api.download(url, `${slug(t('evidence.file_portfolio'), 'portfolio')}-${suffix}`))
  const auditFile = (name: string) => tf('audit.file', { name: slug(name, t('evidence.file_asset')).slice(0, 40), framework })
  const choose = (value: string | null) => { if (!value) return; setChosen(value as Framework); rememberFramework(value as Framework) }

  if (!overview.data) return overview.isError
    ? <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('evidence.load_failed')}</p>
    : <SkeletonCard lines={4} label={t('loading')} />
  const counts = overview.data
  const asset = picked?.asset
  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="text-base">{t('evidence.title')}</CardTitle><CardDescription>{t('evidence.description')}</CardDescription></CardHeader>
    <CardContent className="space-y-5">
      {!counts.assets ? <p className="text-sm text-app-muted">{t('evidence.none')} <button type="button" onClick={onNew} className="min-h-6 text-brand underline-offset-2 hover:underline">{t('evidence.new_scan')}</button></p> : <>
        <div className="max-w-sm space-y-1"><label htmlFor="evidence-framework" className="text-xs text-app-muted">{t('evidence.framework')}</label>
          <Select value={framework} onValueChange={choose}>
            <SelectTrigger id="evidence-framework" className="w-full border-app-line bg-inset">{frameworkName}</SelectTrigger>
            <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{frameworks.map(([id, name]) => <SelectItem key={id} value={id}>{tf(name)}</SelectItem>)}</SelectContent>
          </Select></div>

        <section aria-labelledby="evidence-asset" className="space-y-2">
          <h3 id="evidence-asset" className="text-sm font-medium">{t('evidence.asset_title')}</h3>
          <Combobox className="max-w-sm" label={t('evidence.asset')} placeholder={t('evidence.choose')} emptyText={t('evidence.no_match')} value={picked} search={search}
            onSelect={option => { setPicked(option as ComboOption & { asset: Asset }); setError('') }} />
          {asset ? <ul className="divide-y divide-app-line overflow-hidden rounded-xl border border-app-line">
            <Row name={t('evidence.items.sbom')} hint={asset.sbom ? t('evidence.items.sbom_hint') : t('evidence.items.sbom_missing')} busy={busy === 'sbom'} waiting={busy !== null} unavailable={!asset.sbom}
              onClick={() => void exportFile('sbom', asset, 'sbom.cdx.json', 'all')} />
            <Row name={t('evidence.items.vex')} hint={t('evidence.items.vex_hint')} busy={busy === 'vex'} waiting={busy !== null}
              onClick={() => void exportFile('vex', asset, 'vex.openvex.json', 'all')} />
            <Row name={t('evidence.items.technical')} hint={t('evidence.items.technical_hint')} busy={busy === 'technical'} waiting={busy !== null}
              onClick={() => void exportFile('technical', asset, 'report.pdf', 'open')} />
            <Row name={t('evidence.items.audit')} hint={t('evidence.items.audit_hint', { framework: frameworkName })} busy={busy === 'audit'} waiting={busy !== null}
              onClick={() => void download('audit', () => api.downloadPost('/api/reports/audit', 'audit-report', { asset: asset.key, status: 'all', options: { framework } }, auditFile(asset.name)))} />
          </ul> : <p className="text-xs text-app-subtle">{t('evidence.pick_hint')}</p>}
        </section>

        <section aria-labelledby="evidence-portfolio" className="space-y-2">
          <h3 id="evidence-portfolio" className="text-sm font-medium">{t('evidence.portfolio_title')}</h3>
          <p className="text-xs text-app-muted">{t('evidence.portfolio_summary', { count: counts.assets, complete: counts.complete })}</p>
          <ul className="divide-y divide-app-line overflow-hidden rounded-xl border border-app-line">
            <Row name={t('evidence.items.portfolio_sbom')} hint={counts.complete ? t('evidence.items.portfolio_sbom_hint') : t('evidence.items.portfolio_missing')} busy={busy === 'portfolio_sbom'} waiting={busy !== null} unavailable={!counts.complete}
              onClick={() => void portfolioFile('portfolio_sbom', `/api/evidence/portfolio/sbom?${query({ organization: remembered().organization })}`, 'sbom.cdx.json')} />
            <Row name={t('evidence.items.portfolio_vex')} hint={counts.complete ? t('evidence.items.portfolio_vex_hint') : t('evidence.items.portfolio_missing')} busy={busy === 'portfolio_vex'} waiting={busy !== null} unavailable={!counts.complete}
              onClick={() => void portfolioFile('portfolio_vex', '/api/evidence/portfolio/vex', 'vex.openvex.json')} />
            <Row name={t('evidence.items.portfolio')} hint={t('evidence.items.portfolio_hint', { framework: frameworkName })} busy={busy === 'portfolio'} waiting={busy !== null}
              onClick={() => void download('portfolio', () => api.downloadPost('/api/evidence/portfolio', 'audit-report', { framework }, auditFile(t('evidence.file_portfolio'))))} />
          </ul>
        </section>
        {error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p>}
        <span role="status" className="sr-only">{busy ? t('evidence.preparing') : ''}</span>
      </>}
    </CardContent>
  </Card>
}

// Only an unavailable file disables its button; while another download runs, the click is ignored instead, so the
// focused button keeps the keyboard focus.
function Row({ name, hint, busy, waiting = false, unavailable = false, onClick }: { name: string; hint: ReactNode; busy: boolean; waiting?: boolean; unavailable?: boolean; onClick: () => void }) {
  const { t } = useTranslation('compliance')
  const hintId = useId()
  // Unavailable stays focusable (aria-disabled) so keyboard users still hear why, through the linked hint.
  return <li className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
    <span className="min-w-0"><span className="block text-sm font-medium">{name}</span><span id={hintId} className="block text-xs text-app-muted">{hint}</span></span>
    <Button size="sm" variant="outline" aria-describedby={hintId} aria-disabled={waiting || unavailable || undefined} aria-busy={busy || undefined} aria-label={t('evidence.download_label', { item: name })} onClick={() => { if (!unavailable) onClick() }}
      className={`border-app-line bg-app-soft ${(waiting && !busy) || unavailable ? 'opacity-60' : ''}`}>
      {busy ? <LoaderCircle className="motion-safe:animate-spin" /> : <ArrowDownToLine />}{busy ? t('evidence.preparing') : t('evidence.download')}</Button>
  </li>
}
