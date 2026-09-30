import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ExternalLink, LoaderCircle, Ticket } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Popover, PopoverContent, PopoverTitle, PopoverTrigger } from '@/shared/ui/popover'
import { assetQuery, jiraBatchesQuery, keys, type JiraQueued } from '@/shared/api/queries'
import { formatDate } from '@/shared/i18n/format'
import { byAsset, queueJira, useJiraSettled } from '@/features/integrations/jira-batches'

type Notice = (tone: 'ok' | 'error', text: string) => void
const doneOf = (batch: JiraQueued) => batch.created + batch.existing + batch.skipped + batch.failed
// Finished batches stay visible in the shell for a while, so the outcome can be checked after the toast is gone.
const RECENT_MS = 60 * 60_000

// Background Jira work in the app shell: a compact chip while my queued selections run (or finished recently), with
// their detail in a non-modal panel. Toasts say when one starts and how it ended.
export function JiraBackgroundWork({ onNotice }: { onNotice: Notice }) {
  const { t } = useTranslation('integrations')
  const queryClient = useQueryClient()
  const data = useQuery(jiraBatchesQuery()).data
  const items = data?.items ?? []
  const known = useRef<Set<string> | null>(null)
  const notice = useRef(onNotice)
  useEffect(() => { notice.current = onNotice })
  // A batch that appears while the app is open was just queued from here: say it runs in the background.
  useEffect(() => {
    if (!data) return
    if (known.current) for (const item of data.items) if (!known.current.has(item.batch))
      notice.current('ok', item.queued ? t('jira.background.started', { count: item.queued }) : item.linked ? t('jira.background.nothing', { count: item.linked }) : t('jira.background.none_routed'))
    known.current = new Set(data.items.map(item => item.batch))
  }, [data, t])
  useJiraSettled(batch => {
    notice.current(batch.failed ? 'error' : 'ok', batch.failed
      ? t('jira.background.finished_failed', { count: batch.created, failed: batch.failed })
      : t('jira.background.finished', { count: batch.created }))
    void queryClient.invalidateQueries({ queryKey: keys.runs })
    void queryClient.invalidateQueries({ queryKey: ['assets'] })
  })
  const running = items.filter(item => item.pending > 0)
  // Date.now() only decides whether a finished batch is still worth showing; it doesn't need to re-render on its own.
  const [now] = useState(() => Date.now())
  const recent = items.filter(item => item.pending === 0 && item.finished_at && now - Date.parse(item.finished_at) < RECENT_MS)
  if (!running.length && !recent.length) return null
  const total = running.reduce((sum, item) => sum + item.queued, 0)
  const done = running.reduce((sum, item) => sum + doneOf(item), 0)
  const label = running.length ? t('jira.background.label', { done, total }) : t('jira.background.label_done')
  // Not a live region: it changes on every poll; the toasts announce the start and the end once.
  return <div className="flex">
    <Popover>
      <PopoverTrigger render={<Button variant="outline" size="sm" aria-label={label} className="gap-1.5 border-app-line bg-app-soft text-app-secondary" />}>
        {running.length ? <Ring value={total ? done / total : 0} /> : <Ticket className="size-3.5" />}
        <span className="hidden tabular-nums sm:inline">{running.length ? t('jira.background.chip', { done, total }) : 'Jira'}</span>
      </PopoverTrigger>
      <PopoverContent>
        <PopoverTitle className="text-sm font-semibold">{t('jira.background.title')}</PopoverTitle>
        <p className="mt-0.5 text-xs text-app-subtle">{t('jira.background.help')}</p>
        <ul className="mt-3 space-y-3">{items.slice(0, 10).map(item => <li key={item.batch}><BatchDetail batch={item} /></li>)}</ul>
      </PopoverContent>
    </Popover>
  </div>
}

function Ring({ value }: { value: number }) {
  const circumference = 2 * Math.PI * 6
  return <svg aria-hidden viewBox="0 0 16 16" className="size-4 -rotate-90">
    <circle cx="8" cy="8" r="6" fill="none" strokeWidth="2.5" className="stroke-app-line" />
    <circle cx="8" cy="8" r="6" fill="none" strokeWidth="2.5" strokeLinecap="round" className="stroke-brand motion-safe:transition-all"
      strokeDasharray={circumference} strokeDashoffset={circumference * (1 - Math.min(1, Math.max(0, value)))} />
  </svg>
}

// One queued selection: progress, failures, what no rule routes and what already had an issue (with "create anyway").
export function BatchDetail({ batch }: { batch: JiraQueued }) {
  const { t } = useTranslation('integrations')
  const queryClient = useQueryClient()
  const [review, setReview] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [forced, setForced] = useState(false)
  const queuedNote = useRef<HTMLParagraphElement>(null)
  useEffect(() => { if (forced) queuedNote.current?.focus() }, [forced])
  const done = doneOf(batch)
  const linked = batch.linked_items ?? []
  const force = async () => {
    setBusy(true); setError('')
    try { await queueJira(queryClient, byAsset(linked), true); setForced(true); setConfirming(false) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <div className="space-y-1.5 rounded-lg border border-app-line bg-inset p-3 text-xs">
    <p className="text-sm font-medium">{batch.pending > 0 ? t('jira.queue.progress', { done, total: batch.queued, pending: batch.pending, count: batch.pending })
      : t('jira.background.batch_done', { created: batch.created, count: batch.queued })}</p>
    <div role="progressbar" aria-label={t('jira.queue.progress_label')} aria-valuemin={0} aria-valuemax={Math.max(batch.queued, 1)} aria-valuenow={done} className="h-1.5 overflow-hidden rounded-full bg-app-soft">
      <div className="h-full bg-brand motion-safe:transition-all" style={{ width: `${batch.queued ? Math.round(done / batch.queued * 100) : 100}%` }} /></div>
    <p className="text-app-muted">{[t('jira.queue.findings', { count: batch.findings }), t('jira.export.created', { count: batch.created }), t('jira.export.existing', { count: batch.existing }),
      ...(batch.skipped ? [t('jira.queue.skipped', { count: batch.skipped })] : []), ...(batch.force ? [t('jira.background.forced')] : []),
      batch.finished_at ? t('jira.background.finished_at', { date: formatDate(batch.finished_at) }) : t('jira.background.started_at', { date: formatDate(batch.started_at) })].join(' · ')}</p>
    {batch.failed > 0 && <p className="text-danger">{t('jira.queue.failed', { count: batch.failed })}{batch.last_error ? ` ${t('jira.queue.last_error', { error: batch.last_error })}` : ''}</p>}
    {batch.rejected?.length ? <details><summary className="min-h-6 cursor-pointer py-1 text-warning">{t('jira.queue.rejected', { count: batch.rejected.length })}</summary>
      <ul className="space-y-0.5">{byAsset(batch.rejected).map(group => <li key={group.asset} className="text-app-muted">
        <AssetLabel assetKey={group.asset ?? ''} /> · {t('jira.queue.findings', { count: group.fingerprints.length })} · {batch.rejected?.find(item => item.asset === group.asset)?.error}</li>)}</ul></details> : null}
    {batch.linked > 0 && <div className="space-y-1.5">
      <p className="flex flex-wrap items-center gap-2 text-app-muted">{t('jira.queue.linked', { count: batch.linked })}
        {linked.length > 0 && !forced && <Button size="xs" variant="ghost" aria-expanded={review} onClick={() => setReview(!review)}>{t('jira.background.review')}</Button>}</p>
      {review && !forced && <>
        <ul aria-label={t('jira.background.linked_list')} className="max-h-40 space-y-0.5 overflow-y-auto">{linked.map(item => <li key={item.fingerprint}>
          {item.url ? <a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-6 items-center gap-1 font-mono text-brand hover:underline">{item.key}<ExternalLink className="size-3" /></a> : <span className="font-mono">{item.key}</span>}</li>)}</ul>
        <ForceConfirm count={linked.length} confirming={confirming} busy={busy} onAsk={() => setConfirming(true)} onCancel={() => setConfirming(false)} onConfirm={() => void force()} />
      </>}
      {forced && <p ref={queuedNote} tabIndex={-1} role="status" className="text-app-muted">{t('jira.background.force_queued', { count: linked.length })}</p>}
      {error && <p role="alert" className="text-danger">{error}</p>}
    </div>}
  </div>
}

// "Create anyway" is never the default: it asks first, and says what happens to the issue already linked.
export function ForceConfirm({ count, confirming, busy, onAsk, onCancel, onConfirm }: { count: number; confirming: boolean; busy: boolean; onAsk: () => void; onCancel: () => void; onConfirm: () => void }) {
  const { t } = useTranslation('integrations')
  if (!confirming) return <Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={onAsk}>{t('jira.force.action', { count })}</Button>
  return <div role="group" aria-label={t('jira.force.title')} className="space-y-2 rounded-lg border border-warning-line bg-warning-soft p-2.5 text-xs">
    <p className="text-app-fg">{t('jira.force.explain', { count })}</p>
    <div className="flex flex-wrap justify-end gap-2"><Button size="xs" variant="ghost" autoFocus onClick={onCancel}>{t('common:actions.cancel')}</Button>
      <Button size="xs" disabled={busy} onClick={onConfirm}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('jira.force.confirm', { count })}</Button></div>
  </div>
}

function AssetLabel({ assetKey }: { assetKey: string }) {
  return <>{useQuery(assetQuery(assetKey)).data?.name ?? assetKey}</>
}
