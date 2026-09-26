import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import i18n from '@/shared/i18n'
import { ApiError, api } from '@/shared/api/http'
import { Check, ChevronRight, CircleAlert, CircleCheck, Copy, LoaderCircle, ShieldCheck, TriangleAlert } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'

export type DomainKind = 'web' | 'api' | 'surface'
export type Domain = { id: string; host: string; url: string; kind?: DomainKind; context?: string; txt_name: string; txt_value: string; verified: boolean; registered_at?: string; verified_at?: string | null }
type Reach = { host: string; reachable: boolean; status: string; http_status?: number; detail: string }

// Getters so the label follows the current language wherever it's read.
export const kindLabel: Record<DomainKind, string> = {
  get web() { return i18n.t('sources:domains.kind.web') },
  get api() { return i18n.t('sources:domains.kind.api') },
  get surface() { return i18n.t('sources:domains.kind.surface') },
}
const kinds = [
  { id: 'web', label: 'domains.kind.web', hint: 'domains.kind_hint.web' },
  { id: 'api', label: 'domains.kind.api', hint: 'domains.kind_hint.api' },
  { id: 'surface', label: 'domains.kind.surface', hint: 'domains.kind_hint.surface' },
] as const
// El backend exige https sin puerto ni query; aquí solo completamos el esquema que la gente omite al escribir.
const normalize = (value: string) => { const trimmed = value.trim(); return !trimmed || /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}` }

export function useClipboard() {
  const [copied, setCopied] = useState('')
  return { copied, copy: async (value: string) => { await navigator.clipboard.writeText(value); setCopied(value); window.setTimeout(() => setCopied(''), 1800) } }
}

export function AddDomainDialog({ open, onOpenChange, onAdded }: { open: boolean; onOpenChange: (open: boolean) => void; onAdded: (domain: Domain) => void }) {
  const { t } = useTranslation('sources')
  const [url, setUrl] = useState('')
  const [kind, setKind] = useState<DomainKind>('web')
  const [context, setContext] = useState('')
  const [reach, setReach] = useState<Reach | null>(null)
  const [checking, setChecking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const aborter = useRef<AbortController | null>(null)

  useEffect(() => { if (!open) { setUrl(''); setKind('web'); setContext(''); setReach(null); setError('') } }, [open])
  // El sondeo es informativo: un dominio que no contesta igual se puede registrar.
  useEffect(() => {
    const candidate = normalize(url)
    setReach(null)
    if (!/^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+\/?[^\s?#]*$/i.test(candidate)) return setChecking(false)
    setChecking(true)
    const timer = window.setTimeout(async () => {
      aborter.current?.abort()
      const controller = new AbortController()
      aborter.current = controller
      try {
        setReach(await api.post<Reach>('/api/domains/check', 'check-domain', { url: candidate }, { signal: controller.signal }))
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 400) setReach({ host: '', reachable: false, status: 'invalid', detail: caught.message })
        else if (!(caught instanceof DOMException && caught.name === 'AbortError')) setReach(null)
      }
      finally { setChecking(false) }
    }, 600)
    return () => { window.clearTimeout(timer); setChecking(false) }
  }, [url])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      onAdded(await api.post<Domain>('/api/domains', 'register-domain', { url: normalize(url), kind, context }))
      onOpenChange(false)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }

  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{t('domains.add.title')}</DialogTitle><DialogDescription>{t('domains.add.description')}</DialogDescription></DialogHeader>
    <form onSubmit={submit} className="space-y-5">
      <div className="space-y-2">
        <label htmlFor="domain-url" className="text-sm text-app-secondary">{t('domains.add.domain')}</label>
        <div className="relative">
          <Input id="domain-url" required autoFocus value={url} onChange={event => setUrl(event.target.value)} placeholder={t('domains.add.placeholder')} className="border-app-line bg-app-soft pr-10" />
          <span className="absolute top-1/2 right-3 -translate-y-1/2">{checking ? <LoaderCircle className="size-4 animate-spin text-app-subtle" /> : reach?.reachable ? <CircleCheck className="size-4 text-brand" /> : reach ? <CircleAlert className="size-4 text-warning" /> : null}</span>
        </div>
        {checking && <p className="text-xs text-app-subtle">{t('domains.add.checking')}</p>}
        {reach && <p className={`text-xs ${reach.reachable ? 'text-brand' : 'text-warning'}`}>{reach.reachable ? t('domains.add.reachable') : reach.detail}{reach.reachable && reach.http_status ? ` · HTTPS ${reach.http_status}` : ''}</p>}
      </div>
      <details className="group">
        <summary className="flex cursor-pointer list-none items-center gap-1.5 text-sm text-app-muted"><ChevronRight className="size-4 transition group-open:rotate-90" />{t('domains.add.more')}</summary>
        <div className="mt-4 space-y-4">
          <fieldset className="space-y-2"><legend className="mb-2 text-sm text-app-secondary">{t('domains.add.kind')}</legend>{kinds.map(item => <label key={item.id} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${kind === item.id ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset hover:border-brand/30'}`}><input type="radio" name="domain-kind" value={item.id} checked={kind === item.id} onChange={() => setKind(item.id)} className="mt-0.5 accent-brand" /><span><span className="block text-sm">{t(item.label)}</span><span className="text-xs text-app-subtle">{t(item.hint)}</span></span></label>)}</fieldset>
          <div className="space-y-2"><label htmlFor="domain-context" className="text-sm text-app-secondary">{t('domains.add.context')} <span className="text-app-subtle">{t('domains.add.optional')}</span></label><textarea id="domain-context" rows={3} maxLength={400} value={context} onChange={event => setContext(event.target.value)} placeholder={t('domains.add.context_placeholder')} className="w-full rounded-xl border border-app-line bg-app-soft p-3 text-sm outline-none focus-visible:border-brand/60" /><p className="text-xs text-app-subtle">{t('domains.add.context_note', { length: context.length })}</p></div>
        </div>
      </details>
      {error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error}</p>}
      <DialogFooter><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || !url.trim()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{t('domains.add.title')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

export function VerifyDomainDialog({ domain, onOpenChange, onVerified }: { domain: Domain | null; onOpenChange: (open: boolean) => void; onVerified: (domain: Domain) => void }) {
  const { t } = useTranslation('sources')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const { copied, copy } = useClipboard()
  useEffect(() => { setError('') }, [domain])
  if (!domain) return null
  const verify = async () => {
    setBusy(true); setError('')
    try {
      onVerified(await api.post<Domain>('/api/domains/verify', 'verify-domain', { domain_id: domain.id }))
      onOpenChange(false)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }
  const records = [
    { id: 'name', label: t('domains.verify.record_name'), copyLabel: t('domains.verify.copy_name'), value: domain.txt_name },
    { id: 'value', label: t('domains.verify.record_value'), copyLabel: t('domains.verify.copy_value'), value: domain.txt_value },
  ]
  return <Dialog open onOpenChange={onOpenChange}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{t('domains.verify.title')}</DialogTitle><DialogDescription>{t('domains.verify.description')}</DialogDescription></DialogHeader>
    <div className="flex items-start gap-3 rounded-xl border border-warning-line bg-warning-soft p-4 text-sm text-warning"><TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" /><span><Trans t={t} i18nKey="domains.verify.pending" values={{ host: domain.host }} components={{ b: <strong className="font-medium" /> }} /></span></div>
    <div className="space-y-4 rounded-xl border border-app-line bg-inset p-4">
      <p className="text-sm text-app-muted"><Trans t={t} i18nKey="domains.verify.instructions" components={{ b: <strong className="font-medium text-app-secondary" /> }} /></p>
      {records.map(record => <div key={record.id} className="space-y-1.5"><span className="text-xs text-app-subtle">{record.label}</span><div className="flex items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 py-2"><code className="min-w-0 flex-1 break-all font-mono text-xs text-app-secondary">{record.value}</code><Button type="button" aria-label={record.copyLabel} variant="ghost" size="icon-sm" onClick={() => void copy(record.value)}>{copied === record.value ? <Check /> : <Copy />}</Button></div></div>)}
      <span role="status" className="sr-only">{copied ? t('copied_to_clipboard') : ''}</span>
      <p className="text-xs text-app-subtle">{t('domains.verify.propagation')}</p>
    </div>
    <p className="text-xs text-app-subtle">{t('domains.verify.no_tests')}</p>
    {error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error}</p>}
    <DialogFooter><Button variant="ghost" onClick={() => onOpenChange(false)}>{t('domains.verify.skip')}</Button><Button disabled={busy} onClick={() => void verify()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{t('domains.verify.submit')}</Button></DialogFooter>
  </DialogContent></Dialog>
}
