import { useCallback, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronRight, X } from 'lucide-react'
import { Input } from '@/shared/ui/input'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { CHOICES, EMPTY, LISTS, fittingVariables, mustFill, sourcesFor, type Draft, type Entry, type JiraField, type JiraVariables, type SearchValues, type Source, type Variable } from '@/features/integrations/jira-mapping-model'

const SOURCE_LABEL = { none: 'jira.mapping.source.none', tamandua: 'jira.mapping.source.tamandua', fixed: 'jira.mapping.source.fixed', template: 'jira.mapping.source.template' } as const
const TYPE_LABEL: Record<string, string> = {
  text: 'jira.mapping.type.text', rich_text: 'jira.mapping.type.rich_text', number: 'jira.mapping.type.number', date: 'jira.mapping.type.date',
  datetime: 'jira.mapping.type.datetime', option: 'jira.mapping.type.option', options: 'jira.mapping.type.options', priority: 'jira.mapping.type.priority',
  labels: 'jira.mapping.type.labels', strings: 'jira.mapping.type.strings',
}

// The field mapping of a destination: required fields and mapped ones first, the rest behind "More fields".
export function MappingTable({ fields, variables, draft, errors, onChange, searchValues }: {
  fields: JiraField[]; variables: JiraVariables; draft: Draft; errors: Record<string, string>; onChange: (id: string, entry: Entry) => void; searchValues: SearchValues
}) {
  const { t } = useTranslation('integrations')
  const [more, setMore] = useState(false)
  // Which rows lead is decided once, so a row doesn't jump away while it is being edited.
  const [lead] = useState(() => new Set(fields.filter(field => mustFill(field) || (draft[field.id]?.source ?? 'none') !== 'none').map(field => field.id)))
  const shown = (field: JiraField) => lead.has(field.id) || !!errors[field.id]
  const fillable = fields.filter(field => field.fillable)
  const main = fillable.filter(shown)
  const rest = fillable.filter(field => !shown(field))
  const blocked = fields.filter(field => !field.fillable && field.type !== 'managed')
  const blockedRequired = blocked.filter(field => mustFill(field))
  const blockedOptional = blocked.filter(field => !mustFill(field))
  const row = (field: JiraField) => <MappingRow key={field.id} field={field} variables={variables} entry={draft[field.id] ?? EMPTY} error={errors[field.id]} onChange={entry => onChange(field.id, entry)} searchValues={searchValues} />
  return <div className="space-y-3">
    <div className="overflow-x-auto rounded-xl border border-app-line">
      <table className="w-full text-sm">
        <caption className="sr-only">{t('jira.mapping.caption')}</caption>
        <thead className="border-b border-app-line text-left text-xs text-app-subtle"><tr><th scope="col" className="px-3 py-2 font-normal">{t('jira.mapping.field')}</th><th scope="col" className="px-3 py-2 font-normal">{t('jira.mapping.source_column')}</th><th scope="col" className="px-3 py-2 font-normal">{t('jira.mapping.value')}</th></tr></thead>
        <tbody className="divide-y divide-app-line">
          {main.map(row)}
          {blockedRequired.map(field => <BlockedRow key={field.id} field={field} error={errors[field.id]} />)}
          {more && rest.map(row)}
        </tbody>
      </table>
    </div>
    {rest.length > 0 && <button type="button" aria-expanded={more} onClick={() => setMore(!more)} className="inline-flex min-h-6 items-center gap-1 text-xs text-brand hover:underline">
      <ChevronRight className={`size-3.5 transition motion-reduce:transition-none ${more ? 'rotate-90' : ''}`} />{more ? t('jira.mapping.fewer') : t('jira.mapping.more', { count: rest.length })}</button>}
    {blockedOptional.length > 0 && <details className="text-xs text-app-muted"><summary className="min-h-6 cursor-pointer py-1">{t('jira.mapping.unsupported_summary', { count: blockedOptional.length })}</summary>
      <p className="mt-1">{t('jira.mapping.unsupported_help')}</p>
      <ul className="mt-1 flex flex-wrap gap-1.5">{blockedOptional.map(field => <li key={field.id} className="rounded border border-app-line px-1.5 py-0.5">{field.name}</li>)}</ul></details>}
  </div>
}

function BlockedRow({ field, error }: { field: JiraField; error?: string }) {
  const { t } = useTranslation('integrations')
  return <tr className="align-top"><th scope="row" className="px-3 py-2 text-left font-medium">{field.name}<span className="ml-1.5 text-[11px] font-normal text-danger">{t('jira.mapping.required_mark')}</span></th>
    <td colSpan={2} className="px-3 py-2 text-xs text-app-muted">{t('jira.mapping.unsupported_reason')}{error && <p role="alert" className="mt-1 text-danger">{error}</p>}</td></tr>
}

function MappingRow({ field, variables, entry, error, onChange, searchValues }: { field: JiraField; variables: JiraVariables; entry: Entry; error?: string; onChange: (entry: Entry) => void; searchValues: SearchValues }) {
  const { t } = useTranslation('integrations')
  const id = useId()
  const sources = sourcesFor(field, variables, entry.key)
  const set = (patch: Partial<Entry>) => onChange({ ...entry, ...patch })
  const describedBy = error ? `${id}-error` : undefined
  const control = 'h-8 w-full min-w-0 rounded-lg border border-app-line bg-app-soft px-2 text-sm text-app-fg aria-invalid:border-danger'
  const valueLabel = t('jira.mapping.value_label', { field: field.name })
  let value: React.ReactNode = <span className="text-xs text-app-subtle">{mustFill(field) ? t('jira.mapping.choose_source') : t('jira.mapping.left_empty')}</span>
  if (entry.source === 'tamandua') value = <select id={`${id}-value`} aria-label={valueLabel} aria-invalid={!!error || undefined} aria-describedby={describedBy} value={entry.key} onChange={event => set({ key: event.target.value })} className={control}>
    <option value="">{t('jira.mapping.pick_variable')}</option>{fittingVariables(field, variables, entry.key).map(variable => <option key={variable.key} value={variable.key}>{variable.label}</option>)}</select>
  else if (entry.source === 'template') value = <TemplateInput id={`${id}-value`} label={valueLabel} text={entry.text} variables={variables.variables} invalid={!!error} describedBy={describedBy} onChange={text => set({ text })} />
  else if (entry.source === 'fixed' && field.allowed_truncated && CHOICES.includes(field.type))
    value = <ValueSearch field={field} entry={entry} label={valueLabel} invalid={!!error} describedBy={describedBy} search={searchValues} onChange={onChange} />
  else if (entry.source === 'fixed') value = field.type === 'options'
    ? <select id={`${id}-value`} multiple aria-label={valueLabel} aria-invalid={!!error || undefined} aria-describedby={describedBy} value={entry.values} onChange={event => set({ values: [...event.target.selectedOptions].map(option => option.value) })} className={`${control} h-24 py-1`}>
      {field.allowed.map(option => <option key={option.id} value={option.id}>{option.name}</option>)}</select>
    : field.type === 'option' || field.type === 'priority'
      ? <select id={`${id}-value`} aria-label={valueLabel} aria-invalid={!!error || undefined} aria-describedby={describedBy} value={entry.value} onChange={event => set({ value: event.target.value })} className={control}>
        <option value="">{t('jira.mapping.pick_value')}</option>{field.allowed.map(option => <option key={option.id} value={option.id}>{option.name}</option>)}</select>
      : <Input id={`${id}-value`} aria-label={valueLabel} aria-invalid={!!error || undefined} aria-describedby={describedBy} value={entry.value} onChange={event => set({ value: event.target.value })}
        type={field.type === 'number' ? 'number' : field.type === 'date' ? 'date' : field.type === 'datetime' ? 'datetime-local' : 'text'}
        placeholder={LISTS.includes(field.type) ? t('jira.mapping.list_placeholder') : undefined} className="border-app-line bg-app-soft" />
  return <tr className="align-top">
    <th scope="row" className="px-3 py-2 text-left font-medium"><span className="break-words">{field.name}</span>
      {mustFill(field) && <span className="ml-1.5 text-[11px] font-normal text-danger">{t('jira.mapping.required_mark')}</span>}
      <span className="block text-[11px] font-normal text-app-subtle">{TYPE_LABEL[field.type] ? t(TYPE_LABEL[field.type]) : field.type}{field.allowed_truncated ? ` · ${t('jira.mapping.allowed_truncated')}` : ''}</span></th>
    <td className="w-44 px-3 py-2"><select aria-label={t('jira.mapping.source_label', { field: field.name })} value={entry.source} onChange={event => set({ source: event.target.value as Source })} className={control}>
      {entry.source === 'none' && !sources.includes('none') && <option value="none" disabled>{t('jira.mapping.choose_source')}</option>}
      {sources.map(source => <option key={source} value={source}>{t(SOURCE_LABEL[source])}</option>)}</select></td>
    <td className="min-w-56 px-3 py-2">{value}{error && <p id={`${id}-error`} role="alert" className="mt-1 text-xs text-danger">{error}</p>}</td>
  </tr>
}

// A template: plain text with {{variable}} placeholders, inserted at the cursor from the chips below.
function TemplateInput({ id, label, text, variables, invalid, describedBy, onChange }: {
  id: string; label: string; text: string; variables: Variable[]; invalid: boolean; describedBy?: string; onChange: (text: string) => void
}) {
  const { t } = useTranslation('integrations')
  const area = useRef<HTMLTextAreaElement>(null)
  const insert = (key: string) => {
    const element = area.current
    const token = `{{${key}}}`
    const start = element?.selectionStart ?? text.length
    const end = element?.selectionEnd ?? text.length
    onChange(text.slice(0, start) + token + text.slice(end))
    window.requestAnimationFrame(() => { element?.focus(); element?.setSelectionRange(start + token.length, start + token.length) })
  }
  return <div className="space-y-1.5">
    <textarea ref={area} id={id} aria-label={label} aria-invalid={invalid || undefined} aria-describedby={describedBy} value={text} onChange={event => onChange(event.target.value)} rows={2} maxLength={2000}
      className="w-full rounded-lg border border-app-line bg-app-soft px-2 py-1.5 font-mono text-xs text-app-fg aria-invalid:border-danger" />
    <div role="group" aria-label={t('jira.mapping.insert_label')} className="flex flex-wrap gap-1">{variables.map(variable => <button key={variable.key} type="button" title={variable.label}
      aria-label={t('jira.mapping.insert', { name: variable.label })} onClick={() => insert(variable.key)}
      className="min-h-6 rounded border border-app-line bg-inset px-1.5 font-mono text-[11px] text-app-secondary hover:border-brand/40">{`{{${variable.key}}}`}</button>)}</div>
  </div>
}

// A choice among more values than /fields carries: searched by name on the server; `options` takes several.
export function ValueSearch({ field, entry, label, invalid, describedBy, search, onChange }: {
  field: JiraField; entry: Entry; label: string; invalid: boolean; describedBy?: string; search: SearchValues; onChange: (entry: Entry) => void
}) {
  const { t } = useTranslation('integrations')
  const multiple = field.type === 'options'
  const find = useCallback(async (q: string) => {
    const found = await search(field.id, q)
    return { options: found.items.map(item => ({ id: item.id, label: item.name })), total: found.total }
  }, [search, field.id])
  const pick = (option: ComboOption) => {
    const names = { ...entry.names, [option.id]: option.label }
    if (!multiple) onChange({ ...entry, value: option.id, names })
    else if (!entry.values.includes(option.id)) onChange({ ...entry, values: [...entry.values, option.id], names })
  }
  const current = !multiple && entry.value ? { id: entry.value, label: entry.names[entry.value] ?? entry.value } : null
  return <div className="space-y-1.5">
    <Combobox label={label} placeholder={multiple ? t('jira.mapping.search_values') : t('jira.mapping.search_value')} value={current} search={find} onSelect={pick} delay={250} minChars={1} invalid={invalid} describedBy={describedBy} />
    {multiple && entry.values.length > 0 && <ul aria-label={t('jira.mapping.chosen', { field: field.name })} className="flex flex-wrap gap-1.5">{entry.values.map(id => {
      const name = entry.names[id] ?? id
      return <li key={id} className="inline-flex items-center gap-1 rounded-md border border-app-line bg-inset py-0.5 pr-0.5 pl-2 text-xs">{name}
        <button type="button" aria-label={t('jira.mapping.remove_value', { name })} onClick={() => onChange({ ...entry, values: entry.values.filter(item => item !== id) })}
          className="grid size-6 place-items-center rounded text-app-subtle hover:bg-app-soft hover:text-app-fg"><X className="size-3" /></button></li>
    })}</ul>}
  </div>
}
