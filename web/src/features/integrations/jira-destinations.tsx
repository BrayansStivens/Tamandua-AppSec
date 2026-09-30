import { useCallback, useEffect, useId, useState, type FormEvent } from 'react'
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Check, ChevronDown, LoaderCircle, MoreHorizontal, Plus, Search } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { SkeletonList, SkeletonTable } from '@/shared/ui/loading'
import { ApiError } from '@/shared/api/http'
import { apiPost, type PostResponse } from '@/shared/api/client'
import { jiraFieldValuesQuery, jiraFieldsQuery, jiraIssueTypesQuery, jiraProjectsQuery, jiraVariablesQuery, keys, type JiraRouting } from '@/shared/api/queries'
import { MappingTable } from '@/features/integrations/jira-mapping'
import { buildMapping, initialDraft, type Draft, type FieldSnapshot } from '@/features/integrations/jira-mapping-model'
import { destinationTarget, errorMap, type JiraDestination, type JiraRef } from '@/features/integrations/jira-routing'

type Project = { id: string; key: string; name: string }
type Warning = { field: string; error: string }

export function DestinationsSection({ routing, onRemove }: { routing: JiraRouting; onRemove: (destination: JiraDestination) => void }) {
  const { t } = useTranslation('integrations')
  const [editing, setEditing] = useState<JiraDestination | 'new' | null>(null)
  const [saved, setSaved] = useState<{ name: string; warnings: Warning[]; fields: Record<string, string> } | null>(null)
  const users = (id: string) => routing.rules.filter(rule => rule.destination === id).length
  const full = routing.destinations.length >= (routing.limits.destinations ?? Infinity)
  return <section aria-labelledby="jira-destinations" className="space-y-3">
    <div className="flex flex-wrap items-end justify-between gap-2"><div><h4 id="jira-destinations" className="text-sm font-semibold">{t('jira.destinations.title')}</h4><p className="text-xs text-app-subtle">{t('jira.destinations.help')}</p></div>
      <span className="flex flex-wrap items-center justify-end gap-2">{full && <span id="jira-destinations-full" className="text-xs text-app-subtle">{t('jira.destinations.limit', { max: routing.limits.destinations })}</span>}
        <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={full} aria-describedby={full ? 'jira-destinations-full' : undefined} onClick={() => { setSaved(null); setEditing('new') }}><Plus />{t('jira.destinations.add')}</Button></span></div>
    {saved && <div role="status" className={`rounded-lg border px-3 py-2 text-xs ${saved.warnings.length ? 'border-warning-line bg-warning-soft text-warning' : 'border-success-line bg-success-soft text-success'}`}>
      <p className="font-medium">{saved.warnings.length ? t('jira.destinations.saved_warnings', { name: saved.name, count: saved.warnings.length }) : t('jira.destinations.saved', { name: saved.name })}</p>
      {saved.warnings.length > 0 && <ul className="mt-1 list-disc space-y-0.5 pl-4">{saved.warnings.map(item => <li key={`${item.field}:${item.error}`}>{saved.fields[item.field] ? `${saved.fields[item.field]}: ` : ''}{item.error}</li>)}</ul>}
    </div>}
    {routing.destinations.length === 0
      ? <p className="rounded-lg border border-dashed border-app-line px-4 py-6 text-center text-sm text-app-muted">{t('jira.destinations.empty')}</p>
      : <ul className="divide-y divide-app-line rounded-xl border border-app-line">{routing.destinations.map(destination => {
        const count = users(destination.id)
        return <li key={destination.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
          <div className="min-w-0"><p className="truncate text-sm font-medium">{destination.name}</p>
            <p className="text-xs text-app-subtle"><span className="font-mono">{destinationTarget(destination)}</span> · {t('jira.destinations.fields', { count: Object.keys(destination.mapping).length })} · {count ? t('jira.destinations.used_by', { count }) : t('jira.destinations.unused')}</p>
            {destination.legacy && <p className="mt-0.5 text-xs text-warning">{t('jira.destinations.legacy')}</p>}</div>
          <Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t('jira.destinations.actions', { name: destination.name })} />}><MoreHorizontal /></MenuTrigger>
            <MenuContent><MenuItem onClick={() => { setSaved(null); setEditing(destination) }}>{t('common:actions.edit')}</MenuItem>
              <MenuItem disabled={count > 0} onClick={() => onRemove(destination)}>{count > 0 ? t('jira.destinations.remove_in_use') : t('common:actions.remove')}</MenuItem></MenuContent></Menu>
        </li>
      })}</ul>}
    {editing && <DestinationEditor destination={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={result => { setEditing(null); setSaved(result) }} />}
  </section>
}

// Project, issue type and what goes in each field. Everything comes from Jira: nothing is typed by hand.
export function DestinationEditor({ destination, onClose, onSaved }: {
  destination: JiraDestination | null; onClose: () => void; onSaved: (result: { name: string; warnings: Warning[]; fields: Record<string, string> }) => void
}) {
  const { t } = useTranslation('integrations')
  const id = useId()
  const queryClient = useQueryClient()
  const initialProject = destination ? destination.project as JiraRef : null
  const [name, setName] = useState(destination?.name ?? '')
  const [project, setProject] = useState<Project | null>(initialProject?.key ? { id: initialProject.id ?? initialProject.key, key: initialProject.key, name: initialProject.name ?? initialProject.key } : null)
  const [chosenType, setIssueType] = useState(((destination?.issue_type ?? {}) as JiraRef).id ?? '')
  const [edited, setDraft] = useState<Draft | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const types = useQuery({ ...jiraIssueTypesQuery(project?.key ?? ''), enabled: !!project })
  const available = (types.data?.items ?? []).filter(item => !item.subtask)
  // A destination from earlier versions only knows its issue type by name.
  const legacyType = ((destination?.issue_type ?? {}) as JiraRef).name?.toLowerCase()
  const issueType = chosenType || (project?.key === initialProject?.key && legacyType ? types.data?.items.find(item => item.name.toLowerCase() === legacyType)?.id ?? '' : '')
  const fields = useQuery({ ...jiraFieldsQuery(project?.key ?? '', issueType), enabled: !!project && !!issueType })
  const variables = useQuery(jiraVariablesQuery())
  const sameTarget = !!destination && project?.key === initialProject?.key && issueType === ((destination.issue_type as JiraRef).id ?? issueType)
  // Saved mapping when editing the same project and type (unless it is a legacy one); Tamandua's suggestion otherwise.
  const ready = fields.data && variables.data
  const saved = sameTarget && !!destination && !destination.legacy
  const draft = edited ?? (fields.data ? initialDraft(fields.data.fields, saved ? destination.mapping : fields.data.suggested, saved ? destination.fields as FieldSnapshot : null) : null)

  const searchValues = useCallback((field: string, q: string) => queryClient.fetchQuery(jiraFieldValuesQuery(project?.key ?? '', issueType, field, q)), [queryClient, project?.key, issueType])
  const pickProject = (next: Project) => {
    setProject(next); setIssueType(''); setDraft(null); setErrors({})
    if (!name.trim()) setName(next.name.slice(0, 60))
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    const local: Record<string, string> = {}
    if (!name.trim()) local.name = t('jira.destinations.name_required')
    if (!project) local.project = t('jira.destinations.project_required')
    if (!issueType) local.issue_type = t('jira.destinations.type_required')
    const built = fields.data && draft ? buildMapping(fields.data.fields, draft, t) : null
    Object.assign(local, built?.errors ?? {})
    setErrors(local)
    if (Object.keys(local).length || !built || !project) { setMessage(t('jira.form.check_fields')); return }
    setBusy(true); setMessage('')
    try {
      const result: PostResponse<'/api/integrations/jira/destinations'> = await apiPost('/api/integrations/jira/destinations', 'jira-routing',
        { ...(destination ? { id: destination.id } : {}), name: name.trim(), project: project.key, issue_type: issueType, mapping: built.mapping })
      queryClient.setQueryData(keys.jiraRouting, result.routing)
      void queryClient.invalidateQueries({ queryKey: keys.jira, exact: true })
      onSaved({ name: result.destination.name, warnings: result.warnings, fields: Object.fromEntries((fields.data?.fields ?? []).map(field => [field.id, field.name])) })
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : String(caught))
      if (caught instanceof ApiError) setErrors(errorMap(caught.errors))
    } finally { setBusy(false) }
  }
  const fieldError = (key: string) => errors[key] ? <p id={`${id}-${key}-error`} role="alert" className="text-xs text-danger">{errors[key]}</p> : null
  const invalid = (key: string) => ({ 'aria-invalid': !!errors[key] || undefined, 'aria-describedby': errors[key] ? `${id}-${key}-error` : undefined })
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-3xl">
    <DialogHeader><DialogTitle>{destination ? t('jira.destinations.edit_title', { name: destination.name }) : t('jira.destinations.new_title')}</DialogTitle><DialogDescription>{t('jira.destinations.editor_help')}</DialogDescription></DialogHeader>
    <form onSubmit={save} className="space-y-4" noValidate>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5"><label htmlFor={`${id}-name`} className="text-xs text-app-muted">{t('jira.destinations.name')}</label>
          <Input id={`${id}-name`} value={name} maxLength={60} onChange={event => setName(event.target.value)} placeholder={t('jira.destinations.name_placeholder')} className="border-app-line bg-app-soft" {...invalid('name')} />{fieldError('name')}</div>
        <div className="space-y-1.5"><span id={`${id}-project-label`} className="text-xs text-app-muted">{t('jira.destinations.project')}</span>
          <ProjectPicker labelledBy={`${id}-project-label`} value={project} onChange={pickProject} invalid={invalid('project')} />{fieldError('project')}</div>
      </div>
      {project && <div className="space-y-1.5 sm:w-1/2 sm:pr-1.5"><label htmlFor={`${id}-type`} className="text-xs text-app-muted">{t('jira.destinations.issue_type')}</label>
        {types.isPending ? <SkeletonList rows={1} dense label={t('jira.destinations.loading_types')} />
          : types.isError ? <p role="alert" className="text-xs text-danger">{types.error.message}</p>
          : <select id={`${id}-type`} value={issueType} onChange={event => { setIssueType(event.target.value); setDraft(null); setErrors({}) }} {...invalid('issue_type')}
            className="h-8 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm text-app-fg aria-invalid:border-danger">
            <option value="">{t('jira.destinations.pick_type')}</option>{available.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>}
        {fieldError('issue_type')}</div>}
      {project && issueType && <div className="space-y-2"><div><h5 className="text-sm font-medium">{t('jira.mapping.title')}</h5><p className="text-xs text-app-subtle">{t('jira.mapping.help')}</p></div>
        {fields.isError ? <p role="alert" className="text-xs text-danger">{fields.error.message}</p>
          : ready && draft ? <>
            {fields.data.truncated && <p className="text-xs text-warning">{t('jira.mapping.truncated')}</p>}
            <MappingTable key={`${project.key}:${issueType}`} fields={fields.data.fields} variables={variables.data} draft={draft} errors={errors} onChange={(field, entry) => setDraft({ ...draft, [field]: entry })} searchValues={searchValues} />
          </> : <SkeletonTable rows={4} columns={3} label={t('jira.mapping.loading')} />}</div>}
      {message && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{message}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={busy || (!!project && !!issueType && !draft)}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('jira.destinations.save')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

// Jira projects searched on the server, a page at a time.
function ProjectPicker({ value, onChange, labelledBy, invalid }: { value: Project | null; onChange: (project: Project) => void; labelledBy: string; invalid: Record<string, unknown> }) {
  const { t } = useTranslation('integrations')
  const [open, setOpen] = useState(!value)
  const [text, setText] = useState('')
  const [q, setQ] = useState('')
  useEffect(() => { const timer = window.setTimeout(() => setQ(text.trim()), 250); return () => window.clearTimeout(timer) }, [text])
  const pages = useInfiniteQuery({ ...jiraProjectsQuery(q), enabled: open })
  const items = pages.data?.pages.flatMap(page => page.items) ?? []
  const total = pages.data?.pages[0]?.total ?? 0
  if (!open && value) return <button type="button" aria-labelledby={labelledBy} aria-describedby={`${labelledBy}-value`} onClick={() => setOpen(true)} {...invalid}
    className="flex h-8 w-full items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 text-left text-sm hover:border-brand/40">
    <span id={`${labelledBy}-value`} className="min-w-0 flex-1 truncate"><span className="font-mono">{value.key}</span> · {value.name}</span><ChevronDown className="size-3.5 text-app-subtle" /></button>
  return <div className="space-y-1.5">
    <div className="relative"><Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-app-subtle" />
      <Input aria-labelledby={labelledBy} placeholder={t('jira.destinations.project_search')} value={text} onChange={event => setText(event.target.value)} className="border-app-line bg-app-soft pl-8" {...invalid} /></div>
    <ul aria-labelledby={labelledBy} className="max-h-48 overflow-y-auto rounded-lg border border-app-line">
      {pages.isPending ? <li><SkeletonList rows={3} dense label={t('jira.destinations.loading_projects')} /></li>
        : pages.isError ? <li role="alert" className="px-3 py-2 text-xs text-danger">{pages.error.message}</li>
        : items.length === 0 ? <li className="px-3 py-3 text-xs text-app-subtle">{t('jira.destinations.no_projects')}</li>
        : items.map(project => <li key={project.id}><button type="button" aria-pressed={value?.key === project.key}
          onClick={() => { onChange(project); setOpen(false) }} className="flex min-h-8 w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-app-soft">
          <Check className={`size-3.5 shrink-0 ${value?.key === project.key ? 'text-brand' : 'text-transparent'}`} /><span className="w-16 shrink-0 font-mono text-xs">{project.key}</span><span className="min-w-0 truncate">{project.name}</span></button></li>)}
    </ul>
    <div className="flex items-center justify-between gap-2 text-xs text-app-subtle">
      {items.length > 0 && <span>{t('jira.destinations.projects_shown', { shown: items.length, total })}</span>}
      <span className="ml-auto flex gap-2">{pages.hasNextPage && <Button type="button" size="xs" variant="outline" className="border-app-line bg-app-soft" disabled={pages.isFetchingNextPage} onClick={() => void pages.fetchNextPage()}>{t('jira.destinations.more_projects')}</Button>}
        {value && <Button type="button" size="xs" variant="ghost" onClick={() => setOpen(false)}>{t('common:actions.cancel')}</Button>}</span>
    </div>
  </div>
}
