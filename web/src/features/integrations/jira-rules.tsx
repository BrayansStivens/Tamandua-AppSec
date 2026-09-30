import { useCallback, useId, useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowDown, ArrowUp, LoaderCircle, MoreHorizontal, Plus, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { ApiError, api, query } from '@/shared/api/http'
import { apiPost, type PostBody, type PostResponse, type Response } from '@/shared/api/client'
import { assetQuery, keys, type JiraRouting } from '@/shared/api/queries'
import { formatDate, formatNumber } from '@/shared/i18n/format'
import type { Page } from '@/shared/lib/types'
import { assetOption, type Asset } from '@/features/sources/asset-picker'
import { destinationOf, destinationTarget, errorMap, type JiraRule } from '@/features/integrations/jira-routing'

type Backfill = Response<'/api/integrations/jira/backfill'>['items'][number]
type Preview = PostResponse<'/api/integrations/jira/rules/preview'>
type RuleBody = PostBody<'/api/integrations/jira/rules'>
type Severity = JiraRule['min_severity']
const SEVERITIES = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low', info: 'common:severity.info' } as const
const HISTORY = {
  destination_saved: 'jira.history.destination_saved', destination_removed: 'jira.history.destination_removed', rule_saved: 'jira.history.rule_saved',
  rule_removed: 'jira.history.rule_removed', rules_reordered: 'jira.history.rules_reordered', legacy_adopted: 'jira.history.legacy_adopted',
} as const
const PREVIEW_LIMIT = 3
// Findings one backfill queues at most (BACKFILL_MAX on the server); the rest waits for the next one.
const PREVIEW_MAX = 5000

// An asset stored by key, shown by name.
function AssetName({ assetKey }: { assetKey: string }) {
  const found = useQuery(assetQuery(assetKey)).data
  return <>{found?.name ?? assetKey}</>
}

// The ordered rules: first match wins, the default one last. Moving is by buttons (keyboard and screen readers).
export function RulesSection({ routing, backfills, onRemove }: { routing: JiraRouting; backfills: Backfill[]; onRemove: (rule: JiraRule) => void }) {
  const { t } = useTranslation('integrations')
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<JiraRule | 'new' | null>(null)
  const [refilling, setRefilling] = useState<JiraRule | null>(null)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [moving, setMoving] = useState(false)
  const movable = routing.rules.filter(rule => !rule.default)
  const full = movable.length >= (routing.limits.rules ?? Infinity)
  const move = async (rule: JiraRule, step: -1 | 1) => {
    const ids = movable.map(item => item.id)
    const from = ids.indexOf(rule.id)
    const to = from + step
    if (from < 0 || to < 0 || to >= ids.length) return
    ;[ids[from], ids[to]] = [ids[to], ids[from]]
    setMoving(true); setError('')
    try {
      queryClient.setQueryData(keys.jiraRouting, await apiPost('/api/integrations/jira/rules/order', 'jira-routing', { ids }))
      setNotice(t('jira.rules.moved', { name: rule.name, position: to + 1 }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setMoving(false) }
  }
  const refilled = (rule: JiraRule, queued: number) => {
    void queryClient.invalidateQueries({ queryKey: keys.jiraBackfill })
    setRefilling(null)
    setNotice(t('jira.rules.backfill_started', { name: rule.name, count: queued }))
  }
  const saved = (result: PostResponse<'/api/integrations/jira/rules'>) => {
    queryClient.setQueryData(keys.jiraRouting, result.routing)
    void queryClient.invalidateQueries({ queryKey: keys.jira, exact: true })
    if (result.backfill) void queryClient.invalidateQueries({ queryKey: keys.jiraBackfill })
    setEditing(null)
    setNotice(result.backfill ? t('jira.rules.saved_backfill', { name: result.rule.name, count: result.backfill.queued }) : t('jira.rules.saved', { name: result.rule.name }))
  }
  return <section aria-labelledby="jira-rules" className="space-y-3">
    <div className="flex flex-wrap items-end justify-between gap-2"><div><h4 id="jira-rules" className="text-sm font-semibold">{t('jira.rules.title')}</h4><p className="text-xs text-app-subtle">{t('jira.rules.help')}</p></div>
      <span className="flex flex-wrap items-center justify-end gap-2">{(full || routing.destinations.length === 0) && <span id="jira-rules-blocked" className="text-xs text-app-subtle">{full ? t('jira.rules.limit', { max: routing.limits.rules }) : t('jira.rules.needs_destination')}</span>}
        <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={full || routing.destinations.length === 0} aria-describedby={full || routing.destinations.length === 0 ? 'jira-rules-blocked' : undefined} onClick={() => { setNotice(''); setEditing('new') }}><Plus />{t('jira.rules.add')}</Button></span></div>
    <p role="status" className="text-xs text-app-muted empty:hidden">{notice}</p>
    {error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</p>}
    <ol className="divide-y divide-app-line rounded-xl border border-app-line">{routing.rules.map((rule, index) => {
      const destination = destinationOf(routing, rule.destination)
      const backfill = backfills.find(item => item.rule === rule.id)
      return <li key={rule.id} className="flex items-start gap-3 px-3 py-2.5">
        <span aria-hidden className="mt-0.5 w-5 shrink-0 text-right font-mono text-xs text-app-subtle">{index + 1}</span>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-x-2 text-sm font-medium"><span className="truncate">{rule.name}</span>
            {!rule.enabled && <span className="rounded border border-app-line px-1.5 text-[11px] font-normal text-app-muted">{t('jira.rules.off')}</span>}
            <span className={`rounded border px-1.5 text-[11px] font-normal ${rule.mode === 'auto' ? 'border-info-line text-info' : 'border-app-line text-app-muted'}`}>{rule.mode === 'auto' ? t('jira.rules.auto_from', { severity: t(SEVERITIES[rule.min_severity]) }) : t('jira.rules.manual')}</span></p>
          <p className="text-xs text-app-subtle">{rule.default ? t('jira.rules.matches_rest') : <Matches rule={rule} />}</p>
          <p className="text-xs text-app-muted">{destination ? <>{t('jira.rules.to', { name: destination.name })} · <span className="font-mono">{destinationTarget(destination)}</span></> : t('jira.rules.no_destination')}</p>
          {backfill && <BackfillLine backfill={backfill} />}
        </div>
        <div className="flex shrink-0 items-center gap-0.5">
          {!rule.default && <>
            <Button size="icon-xs" variant="ghost" aria-label={t('jira.rules.move_up', { name: rule.name })} disabled={moving || index === 0} onClick={() => void move(rule, -1)}><ArrowUp /></Button>
            <Button size="icon-xs" variant="ghost" aria-label={t('jira.rules.move_down', { name: rule.name })} disabled={moving || index === movable.length - 1} onClick={() => void move(rule, 1)}><ArrowDown /></Button>
          </>}
          <Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t('jira.rules.actions', { name: rule.name })} />}><MoreHorizontal /></MenuTrigger>
            <MenuContent><MenuItem onClick={() => { setNotice(''); setEditing(rule) }}>{t('common:actions.edit')}</MenuItem>
              {rule.mode === 'auto' && rule.enabled && rule.destination && <MenuItem onClick={() => { setError(''); setRefilling(rule) }}>{t('jira.rules.rerun_backfill')}</MenuItem>}
              {!rule.default && <MenuItem onClick={() => onRemove(rule)}>{t('common:actions.remove')}</MenuItem>}</MenuContent></Menu>
        </div>
      </li>
    })}</ol>
    {editing && <RuleEditor rule={editing === 'new' ? null : editing} routing={routing} onClose={() => setEditing(null)} onSaved={saved} />}
    {refilling && <BackfillConfirm rule={refilling} onClose={() => setRefilling(null)} onStarted={queued => refilled(refilling, queued)} />}
  </section>
}

function Matches({ rule }: { rule: JiraRule }) {
  const { t } = useTranslation('integrations')
  const items = [...rule.assets.map(key => ({ key, pattern: false })), ...rule.patterns.map(key => ({ key, pattern: true }))]
  const list = <span>{items.slice(0, PREVIEW_LIMIT).map((item, index) => <span key={`${item.pattern}:${item.key}`}>{index ? ', ' : ''}{item.pattern ? <code className="font-mono">{item.key}</code> : <AssetName assetKey={item.key} />}</span>)}</span>
  return items.length > PREVIEW_LIMIT
    ? <Trans t={t} i18nKey="jira.rules.matches_more" count={items.length - PREVIEW_LIMIT} components={{ items: list }} />
    : <Trans t={t} i18nKey="jira.rules.matches" components={{ items: list }} />
}

// Running a backfill again queues issues at once: first say how many, then confirm.
function BackfillConfirm({ rule, onClose, onStarted }: { rule: JiraRule; onClose: () => void; onStarted: (queued: number) => void }) {
  const { t } = useTranslation('integrations')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // The preview only counts (nothing is queued): a read, even if it is a POST.
  const check = useQuery({ queryKey: ['jira', 'preview', rule.id], gcTime: 0, queryFn: () => apiPost('/api/integrations/jira/rules/preview', 'jira-preview', {
    id: rule.id, ...(rule.default ? {} : { name: rule.name, assets: rule.assets, patterns: rule.patterns }), destination: rule.destination ?? null,
    mode: rule.mode, min_severity: rule.min_severity, backfill: true, enabled: rule.enabled }) })
  const preview = check.data
  const start = async () => {
    setBusy(true); setError('')
    try { onStarted((await apiPost('/api/integrations/jira/rules/backfill', 'jira-routing', { id: rule.id })).queued) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); setBusy(false) }
  }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-md">
    <DialogHeader><DialogTitle>{t('jira.rules.rerun_title', { name: rule.name })}</DialogTitle><DialogDescription>{t('jira.rules.backfill_help')}</DialogDescription></DialogHeader>
    <p role="status" className="text-sm text-app-muted">{preview ? <PreviewText preview={preview} /> : check.isPending ? t('jira.preview.checking') : null}</p>
    {(error || check.isError) && <p role="alert" className="text-xs text-danger">{error || check.error?.message}</p>}
    <DialogFooter><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button disabled={busy || !preview?.issues} onClick={() => void start()}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('jira.rules.rerun_confirm', { count: preview?.issues ?? 0 })}</Button></DialogFooter>
  </DialogContent></Dialog>
}

function PreviewText({ preview }: { preview: Preview }) {
  const { t } = useTranslation('integrations')
  return <>{preview.findings
    ? t('jira.preview.result', { findings: formatNumber(preview.findings), assets: formatNumber(preview.assets), issues: formatNumber(preview.issues), linked: formatNumber(preview.linked), count: preview.issues })
    : t('jira.preview.nothing', { linked: formatNumber(preview.linked) })}{preview.truncated ? ` ${t('jira.preview.truncated', { max: formatNumber(PREVIEW_MAX) })}` : ''}</>
}

function BackfillLine({ backfill }: { backfill: Backfill }) {
  const { t } = useTranslation('integrations')
  const running = backfill.pending > 0
  const counts = [
    t('jira.backfill.created', { count: backfill.created }), t('jira.backfill.existing', { count: backfill.existing }),
    ...(backfill.failed ? [t('jira.backfill.failed', { count: backfill.failed })] : []), ...(backfill.skipped ? [t('jira.backfill.skipped', { count: backfill.skipped })] : []),
    ...(running ? [t('jira.backfill.pending', { count: backfill.pending })] : []),
  ].join(' · ')
  return <div className="mt-1 text-xs" role={running ? 'status' : undefined}>
    <p className={backfill.failed ? 'text-warning' : 'text-app-muted'}>{running ? t('jira.backfill.running', { count: backfill.queued }) : t('jira.backfill.done', { count: backfill.queued, date: backfill.finished_at ? formatDate(backfill.finished_at) : '—' })} · {counts}{backfill.truncated ? ` · ${t('jira.backfill.truncated')}` : ''}</p>
    {backfill.last_error && <p className="text-danger">{t('jira.backfill.last_error', { error: backfill.last_error })}</p>}
  </div>
}

type RuleDraft = { name: string; assets: string[]; patterns: string; destination: string; mode: 'manual' | 'auto'; min_severity: Severity; backfill: boolean; enabled: boolean }
const draftOf = (rule: JiraRule | null, routing: JiraRouting): RuleDraft => rule
  ? { name: rule.name, assets: rule.assets, patterns: rule.patterns.join('\n'), destination: rule.destination ?? '', mode: rule.mode, min_severity: rule.min_severity, backfill: rule.backfill, enabled: rule.enabled }
  : { name: '', assets: [], patterns: '', destination: routing.destinations.length === 1 ? routing.destinations[0].id : '', mode: 'manual', min_severity: 'high', backfill: false, enabled: true }
const bodyOf = (rule: JiraRule | null, draft: RuleDraft): RuleBody => ({
  ...(rule ? { id: rule.id } : {}), ...(rule?.default ? {} : { name: draft.name.trim(), assets: draft.assets, patterns: draft.patterns.split('\n').map(item => item.trim()).filter(Boolean) }),
  destination: draft.destination || null, mode: draft.mode, min_severity: draft.min_severity, backfill: draft.mode === 'auto' && draft.backfill, enabled: draft.enabled,
})

// A rule: which assets, where their issues go and whether Tamandua creates them on its own.
export function RuleEditor({ rule, routing, onClose, onSaved }: { rule: JiraRule | null; routing: JiraRouting; onClose: () => void; onSaved: (result: PostResponse<'/api/integrations/jira/rules'>) => void }) {
  const { t } = useTranslation('integrations')
  const id = useId()
  const [draft, setDraft] = useState(() => draftOf(rule, routing))
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState<{ for: string; result: Preview } | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const set = (patch: Partial<RuleDraft>) => setDraft(current => ({ ...current, ...patch }))
  const body = bodyOf(rule, draft)
  const snapshot = JSON.stringify(body)
  const wantsBackfill = body.backfill && body.enabled
  const previewCurrent = preview?.for === snapshot
  const isDefault = !!rule?.default
  const fail = (caught: unknown) => {
    setMessage(caught instanceof Error ? caught.message : String(caught))
    if (caught instanceof ApiError) setErrors(errorMap(caught.errors))
  }
  const runPreview = async () => {
    setPreviewing(true); setMessage(''); setErrors({})
    try { setPreview({ for: snapshot, result: await apiPost('/api/integrations/jira/rules/preview', 'jira-preview', body) }) } catch (caught) { fail(caught) } finally { setPreviewing(false) }
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (wantsBackfill && !previewCurrent) { await runPreview(); return }
    setBusy(true); setMessage(''); setErrors({})
    try { onSaved(await apiPost('/api/integrations/jira/rules', 'jira-routing', body)) } catch (caught) { fail(caught) } finally { setBusy(false) }
  }
  const fieldError = (key: string) => errors[key] ? <p id={`${id}-${key}-error`} role="alert" className="text-xs text-danger">{errors[key]}</p> : null
  const invalid = (key: string) => ({ 'aria-invalid': !!errors[key] || undefined, 'aria-describedby': errors[key] ? `${id}-${key}-error` : undefined })
  const control = 'h-8 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm text-app-fg aria-invalid:border-danger'
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-2xl">
    <DialogHeader><DialogTitle>{rule ? t('jira.rules.edit_title', { name: rule.name }) : t('jira.rules.new_title')}</DialogTitle><DialogDescription>{isDefault ? t('jira.rules.default_help') : t('jira.rules.editor_help')}</DialogDescription></DialogHeader>
    <form onSubmit={save} className="space-y-4" noValidate>
      {!isDefault && <>
        <div className="space-y-1.5"><label htmlFor={`${id}-name`} className="text-xs text-app-muted">{t('jira.rules.name')}</label>
          <Input id={`${id}-name`} value={draft.name} maxLength={60} onChange={event => set({ name: event.target.value })} placeholder={t('jira.rules.name_placeholder')} className="border-app-line bg-app-soft" {...invalid('name')} />{fieldError('name')}</div>
        <AssetsField label={t('jira.rules.assets')} value={draft.assets} max={routing.limits.assets ?? 200} onChange={assets => set({ assets })} error={fieldError('assets')} invalid={!!errors.assets} describedBy={errors.assets ? `${id}-assets-error` : undefined} />
        <div className="space-y-1.5"><label htmlFor={`${id}-patterns`} className="text-xs text-app-muted">{t('jira.rules.patterns')}</label>
          <textarea id={`${id}-patterns`} rows={2} value={draft.patterns} onChange={event => set({ patterns: event.target.value })} placeholder="org/payments-*" {...invalid('patterns')}
            aria-describedby={errors.patterns ? `${id}-patterns-error` : `${id}-patterns-help`} className="w-full rounded-lg border border-app-line bg-app-soft px-2 py-1.5 font-mono text-xs text-app-fg aria-invalid:border-danger" />
          <p id={`${id}-patterns-help`} className="text-xs text-app-subtle">{t('jira.rules.patterns_help')}</p>{fieldError('patterns')}</div>
      </>}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5"><label htmlFor={`${id}-destination`} className="text-xs text-app-muted">{t('jira.rules.destination')}</label>
          <select id={`${id}-destination`} value={draft.destination} onChange={event => set({ destination: event.target.value })} className={control} {...invalid('destination')}>
            <option value="">{t('jira.rules.pick_destination')}</option>{routing.destinations.map(item => <option key={item.id} value={item.id}>{item.name} · {destinationTarget(item)}</option>)}</select>{fieldError('destination')}</div>
        <div className="flex items-end pb-1.5"><label className="inline-flex min-h-6 items-center gap-2 text-sm"><input type="checkbox" checked={draft.enabled} onChange={event => set({ enabled: event.target.checked })} className="size-4 accent-brand" />{t('jira.rules.enabled')}</label></div>
      </div>
      <fieldset className="space-y-2"><legend className="text-xs text-app-muted">{t('jira.rules.mode')}</legend>
        <div className="grid gap-2 sm:grid-cols-2">{(['manual', 'auto'] as const).map(mode => <label key={mode}
          className={`flex cursor-pointer items-start gap-2 rounded-lg border p-3 ${draft.mode === mode ? 'border-brand/50 bg-brand/10' : 'border-app-line bg-app-soft'}`}>
          <input type="radio" name={`${id}-mode`} value={mode} checked={draft.mode === mode} onChange={() => set({ mode })} className="mt-0.5 size-4 accent-brand" />
          <span><span className="block text-sm font-medium">{mode === 'auto' ? t('jira.rules.mode_auto') : t('jira.rules.mode_manual')}</span>
            <span className="block text-xs text-app-muted">{mode === 'auto' ? t('jira.rules.mode_auto_help') : t('jira.rules.mode_manual_help')}</span></span></label>)}</div></fieldset>
      {draft.mode === 'auto' && <div className="space-y-3 rounded-lg border border-app-line bg-inset p-3">
        <div className="space-y-1.5 sm:w-1/2"><label htmlFor={`${id}-severity`} className="text-xs text-app-muted">{t('jira.rules.min_severity')}</label>
          <select id={`${id}-severity`} value={draft.min_severity} onChange={event => set({ min_severity: event.target.value as Severity })} className={control} {...invalid('min_severity')}>
            {(Object.keys(SEVERITIES) as Severity[]).map(level => <option key={level} value={level}>{t('jira.rules.at_least', { severity: t(SEVERITIES[level]) })}</option>)}</select>{fieldError('min_severity')}</div>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={draft.backfill} onChange={event => set({ backfill: event.target.checked })} className="mt-0.5 size-4 accent-brand" />
          <span>{t('jira.rules.backfill')}<span className="block text-xs text-app-subtle">{t('jira.rules.backfill_help')}</span></span></label>
        {wantsBackfill && <div role="status" className="rounded-lg border border-app-line bg-panel px-3 py-2 text-xs">
          {previewCurrent && preview ? <p><PreviewText preview={preview.result} /></p>
            : <p className="text-app-muted">{preview ? t('jira.preview.outdated') : t('jira.preview.needed')}</p>}
          {!previewCurrent && <Button type="button" size="xs" variant="outline" className="mt-2 border-app-line bg-app-soft" disabled={previewing} onClick={() => void runPreview()}>{previewing && <LoaderCircle className="motion-safe:animate-spin" />}{t('jira.preview.run')}</Button>}
        </div>}
      </div>}
      {message && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{message}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={busy || previewing}>{(busy || previewing) && <LoaderCircle className="motion-safe:animate-spin" />}{wantsBackfill && previewCurrent && preview?.result.issues ? t('jira.rules.save_backfill', { count: preview.result.issues }) : t('jira.rules.save')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

// Assets picked by name (server search), kept by key.
function AssetsField({ label, value, max, onChange, error, invalid, describedBy }: { label: string; value: string[]; max: number; onChange: (keys: string[]) => void; error: React.ReactNode; invalid: boolean; describedBy?: string }) {
  const { t } = useTranslation('integrations')
  const id = useId()
  const search = useCallback(async (text: string) => {
    const page = await api.get<Page<Asset>>(`/api/assets?${query({ q: text || undefined, limit: 50 })}`)
    return { options: page.items.map(assetOption), total: page.total }
  }, [])
  const add = (option: ComboOption) => { if (!value.includes(option.id) && value.length < max) onChange([...value, option.id]) }
  return <div className="space-y-1.5">
    <span id={`${id}-label`} className="text-xs text-app-muted">{label}</span>
    <Combobox label={label} placeholder={t('jira.rules.assets_placeholder')} value={null} search={search} onSelect={add} invalid={invalid} describedBy={describedBy} />
    {value.length > 0 && <ul aria-labelledby={`${id}-label`} className="flex flex-wrap gap-1.5">{value.map(key => <li key={key} className="inline-flex items-center gap-1 rounded-md border border-app-line bg-inset py-0.5 pr-0.5 pl-2 text-xs">
      <AssetName assetKey={key} /><RemoveAsset assetKey={key} onRemove={() => onChange(value.filter(item => item !== key))} /></li>)}</ul>}
    {error}
  </div>
}

function RemoveAsset({ assetKey, onRemove }: { assetKey: string; onRemove: () => void }) {
  const { t } = useTranslation('integrations')
  const name = useQuery(assetQuery(assetKey)).data?.name ?? assetKey
  return <button type="button" aria-label={t('jira.rules.remove_asset', { name })} onClick={onRemove} className="grid size-6 place-items-center rounded text-app-subtle hover:bg-app-soft hover:text-app-fg"><X className="size-3" /></button>
}

// Recent changes, newest first; ids are shown by the name they have now.
export function RoutingHistory({ routing }: { routing: JiraRouting }) {
  const { t } = useTranslation('integrations')
  if (!routing.history.length) return null
  const nameOf = (target: string) => {
    const first = target.split(/\s/)[0]
    return routing.rules.find(item => item.id === first)?.name ?? routing.destinations.find(item => item.id === first)?.name ?? target
  }
  return <details className="group rounded-xl border border-app-line"><summary className="min-h-6 cursor-pointer px-4 py-2.5 text-sm font-medium">{t('jira.history.title', { count: routing.history.length })}</summary>
    <ul className="space-y-1 px-4 pb-3 text-xs text-app-muted">{routing.history.map((entry, index) => {
      const item = entry as { at?: string; by?: string; action?: string; target?: string }
      const action = t(item.action && item.action in HISTORY ? HISTORY[item.action as keyof typeof HISTORY] : 'jira.history.changed', { target: nameOf(item.target ?? '') })
      return <li key={index}><span className="text-app-subtle">{item.at ? formatDate(item.at) : '—'}</span> · {item.by || t('jira.history.someone')} · {action}</li>
    })}</ul></details>
}
