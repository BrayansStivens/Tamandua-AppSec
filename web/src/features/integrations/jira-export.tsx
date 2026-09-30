import { useId, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ExternalLink, LoaderCircle, Ticket } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { apiPost, type PostBody, type PostResponse } from '@/shared/api/client'
import { queueJira } from '@/features/integrations/jira-batches'
import { ForceConfirm } from '@/features/integrations/jira-background'
import type { JiraAvailability } from '@/features/integrations/jira-availability'

export type TicketLink = { key: string; url: string; by?: string; linked_at?: string; project?: string | null; destination?: string | null }
// Which findings to send: from a run, or from an asset's current state.
export type JiraSelection = { runId: string } | { asset: string }
export type JiraFindingRef = { fingerprint: string; label: string }
type ExportResult = PostResponse<'/api/integrations/jira/issues'>
type ExportItem = ExportResult['created'][number]
// Up to this many findings are created while the dialog waits; more go through the queue, in the background.
export const JIRA_SYNC_MAX = 50
export const JIRA_QUEUE_MAX = 5000

// One finding's Jira action: its issue when it has one; otherwise "Create in Jira", or why it can't be created.
export function JiraFindingAction({ ticket, pending, availability, name, onCreate }: {
  ticket?: TicketLink; pending: boolean; availability: JiraAvailability; name: string; onCreate: () => void
}) {
  const { t } = useTranslation('integrations')
  const reason = useId()
  if (ticket) return <a href={ticket.url} target="_blank" rel="noopener noreferrer" aria-label={t('jira.finding.open_issue', { key: ticket.key })}
    className="inline-flex min-h-6 items-center gap-1 font-mono text-xs text-brand hover:underline"><Ticket className="size-3" />{ticket.key}<ExternalLink className="size-3" /></a>
  if (!pending || !availability.ready) return null
  return <span className="inline-flex flex-wrap items-center gap-1.5">
    <Button size="xs" variant="outline" className="border-app-line bg-app-soft" disabled={!!availability.blocked} aria-describedby={availability.blocked ? reason : undefined}
      aria-label={t('jira.finding.create_label', { name })} onClick={onCreate}><Ticket />{t('jira.finding.create')}</Button>
    {availability.blocked && <span id={reason} className="text-[11px] text-app-subtle">{availability.blocked}</span>}
  </span>
}

// Sends the findings, then says per finding which issue (and project) it got, or why it failed.
export function JiraExportDialog({ selection, findings, target, onClose, onDone }: {
  selection: JiraSelection; findings: JiraFindingRef[] | null; target?: string | null; onClose: () => void; onDone: () => void
}) {
  const { t } = useTranslation('integrations')
  const [result, setResult] = useState<ExportResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const queryClient = useQueryClient()
  if (!findings) return null
  const fingerprints = findings.map(item => item.fingerprint)
  const large = findings.length > JIRA_SYNC_MAX
  const selectionOf = (prints: string[]) => 'runId' in selection ? { run_id: selection.runId, fingerprints: prints } : { asset: selection.asset, fingerprints: prints }
  // A large selection goes to the queue and the dialog closes: the shell follows it in the background.
  const run = async (prints = fingerprints, force = false) => {
    setBusy(true); setError('')
    try {
      if (large && !force) { await queueJira(queryClient, [selectionOf(prints)]); onClose(); return }
      const body: PostBody<'/api/integrations/jira/issues'> = force ? { ...selectionOf(prints), force: true } : selectionOf(prints)
      setResult(await apiPost('/api/integrations/jira/issues', 'export-jira', body)); setConfirming(false); onDone()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const label = (fingerprint: string) => findings.find(item => item.fingerprint === fingerprint)?.label ?? fingerprint.slice(0, 12)

  // Advisories of one package share an issue: each issue is listed once, with the findings it covers.
  const issues = new Map<string, ExportItem & { state: 'created' | 'existing'; covered: string[] }>()
  for (const [items, state] of [[result?.created ?? [], 'created'], [result?.existing ?? [], 'existing']] as const)
    for (const item of items) {
      const key = item.key ?? item.fingerprint
      const entry = issues.get(key)
      if (entry) entry.covered.push(label(item.fingerprint)); else issues.set(key, { ...item, state, covered: [label(item.fingerprint)] })
    }
  const links = [...issues.values()]
  const created = links.filter(item => item.state === 'created').length
  const summary = result ? [
    t('jira.export.created', { count: created }), t('jira.export.existing', { count: links.length - created }),
    ...(result.failed.length ? [t('jira.export.failed', { count: result.failed.length })] : []),
  ].join(' · ') : `${target ? t('jira.export.intro_target', { target }) : t('jira.export.intro')}${large ? ` ${t('jira.queue.intro', { max: JIRA_SYNC_MAX })}` : ''}`
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t('jira.export.title', { count: findings.length })}</DialogTitle><DialogDescription>{summary}</DialogDescription></DialogHeader>
    {links.length > 0 && <ul aria-label={t('jira.export.issues')} className="max-h-72 space-y-2 overflow-y-auto text-sm">{links.map(item => <li key={item.key ?? item.fingerprint} className="rounded-lg border border-app-line bg-inset px-3 py-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {item.url ? <a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-brand hover:underline">{item.key}<ExternalLink className="size-3" /></a> : <span className="font-mono">{item.key}</span>}
        <span className="text-xs text-app-subtle">{item.state === 'created' ? t('jira.export.state.created_in', { project: item.project ?? '—' }) : t('jira.export.state.existing_in', { project: item.project ?? '—' })}</span>
      </div>
      <p className="mt-0.5 truncate text-xs text-app-muted">{item.covered.length > 1 ? t('jira.export.covers', { count: item.covered.length - 1, first: item.covered[0] }) : item.covered[0]}</p>
    </li>)}</ul>}
    {result && result.existing.length > 0 && <ForceConfirm count={result.existing.length} confirming={confirming} busy={busy} onAsk={() => setConfirming(true)} onCancel={() => setConfirming(false)}
      onConfirm={() => void run(result.existing.map(item => item.fingerprint), true)} />}
    {result?.failed.length ? <div role="alert" className="space-y-1"><p className="text-xs font-medium text-danger">{t('jira.export.failed_title')}</p>
      <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">{result.failed.map(item => <li key={item.fingerprint} className="rounded-lg border border-danger-line bg-danger-soft px-3 py-1.5 text-danger">
        <span className="font-medium">{label(item.fingerprint)}</span> · {item.error}</li>)}</ul></div> : null}
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    <DialogFooter>{result ? <Button variant={confirming ? 'outline' : 'default'} onClick={onClose}>{t('jira.export.done')}</Button> : <><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button disabled={busy} onClick={() => void run()}>{busy ? <LoaderCircle className="motion-safe:animate-spin" /> : <Ticket />}{t('jira.export.submit', { count: findings.length })}</Button></>}</DialogFooter>
  </DialogContent></Dialog>
}

