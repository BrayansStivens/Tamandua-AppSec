import type { TFunction } from 'i18next'
import type { Response } from '@/shared/api/client'
import type { JiraFields } from '@/shared/api/queries'

export type JiraField = JiraFields['fields'][number]
export type JiraVariables = Response<'/api/integrations/jira/variables'>
export type JiraFieldValues = Response<'/api/integrations/jira/projects/{project}/issue-types/{issue_type}/fields/{field}/values'>
// Searches one field's allowed values on the server (fields with more values than /fields carries).
export type SearchValues = (field: string, q: string) => Promise<JiraFieldValues>
// What a saved destination remembers of each mapped field: the chosen values' names among them.
export type FieldSnapshot = Record<string, { allowed?: unknown } | undefined> | null | undefined
export type Variable = JiraVariables['variables'][number]
export type Source = 'none' | 'tamandua' | 'fixed' | 'template'
// One row being edited: every source keeps what was typed, so switching back and forth loses nothing.
export type Entry = { source: Source; key: string; value: string; values: string[]; text: string; names: Record<string, string> }
export type Draft = Record<string, Entry>
export type MappingSpec = { source: 'tamandua'; key: string } | { source: 'fixed'; value: string | number | string[] } | { source: 'template'; text: string }

export const TEMPLATED = ['text', 'rich_text', 'labels', 'strings']
export const LISTS = ['labels', 'strings']
export const CHOICES = ['option', 'priority', 'options']
export const EMPTY: Entry = { source: 'none', key: '', value: '', values: [], text: '', names: {} }

export const mustFill = (field: JiraField) => field.required && !field.has_default

// The variables that fit a field (the server's `fits` and `by_name`), plus the one already chosen so a saved mapping always shows.
export function fittingVariables(field: JiraField, variables: JiraVariables, current?: string): Variable[] {
  const fits = variables.fits[field.type] ?? []
  const named = variables.by_name?.[field.type] ?? []
  return variables.variables.filter(variable => fits.includes(variable.type) || named.includes(variable.key) || variable.key === current)
}

export function sourcesFor(field: JiraField, variables: JiraVariables, current?: string): Source[] {
  if (!field.fillable) return []
  const sources: Source[] = []
  if (fittingVariables(field, variables, current).length) sources.push('tamandua')
  if (!CHOICES.includes(field.type) || field.allowed.length) sources.push('fixed')
  if (TEMPLATED.includes(field.type)) sources.push('template')
  if (!mustFill(field)) sources.push('none')
  return sources
}

// Names of allowed values by id: the first page from /fields plus what the destination kept of its choices.
function namesOf(field: JiraField, snapshot?: { allowed?: unknown }): Record<string, string> {
  const kept = Array.isArray(snapshot?.allowed) ? snapshot.allowed as { id?: unknown; name?: unknown }[] : []
  return Object.fromEntries([...field.allowed, ...kept].filter(item => typeof item.id === 'string').map(item => [item.id as string, String(item.name ?? item.id)]))
}

export function entryFrom(field: JiraField, spec: Record<string, unknown> | null | undefined, snapshot?: { allowed?: unknown }): Entry {
  if (!spec || !field.fillable) return EMPTY
  const names = CHOICES.includes(field.type) ? namesOf(field, snapshot) : {}
  if (spec.source === 'tamandua' && typeof spec.key === 'string') return { ...EMPTY, source: 'tamandua', key: spec.key }
  if (spec.source === 'template' && typeof spec.text === 'string') return { ...EMPTY, source: 'template', text: spec.text }
  if (spec.source === 'fixed') {
    const value = spec.value
    if (field.type === 'options') return { ...EMPTY, source: 'fixed', values: Array.isArray(value) ? value.map(String) : [], names }
    return { ...EMPTY, source: 'fixed', value: Array.isArray(value) ? value.join(', ') : value === null || value === undefined ? '' : String(value), names }
  }
  return EMPTY
}

export function initialDraft(fields: JiraField[], mapping: Record<string, Record<string, unknown> | null | undefined>, snapshot?: FieldSnapshot): Draft {
  return Object.fromEntries(fields.filter(field => field.fillable).map(field => [field.id, entryFrom(field, mapping[field.id], snapshot?.[field.id])]))
}

// What the API takes for one row: a spec, null (left empty) or 'incomplete' (a source chosen without its value).
export function specOf(field: JiraField, entry: Entry): MappingSpec | null | 'incomplete' | 'number' {
  if (entry.source === 'none') return null
  if (entry.source === 'tamandua') return entry.key ? { source: 'tamandua', key: entry.key } : 'incomplete'
  if (entry.source === 'template') return entry.text.trim() ? { source: 'template', text: entry.text } : 'incomplete'
  if (field.type === 'options') return entry.values.length ? { source: 'fixed', value: entry.values } : 'incomplete'
  const value = entry.value.trim()
  if (!value) return 'incomplete'
  if (field.type === 'number') return Number.isFinite(Number(value)) ? { source: 'fixed', value: Number(value) } : 'number'
  if (LISTS.includes(field.type)) {
    const items = value.split(',').map(item => item.trim()).filter(Boolean)
    return items.length ? { source: 'fixed', value: items } : 'incomplete'
  }
  return { source: 'fixed', value: field.type === 'text' || field.type === 'rich_text' ? entry.value : value }
}

// The mapping to send (fields left empty go as null: an empty object would mean "use the suggested mapping"), or
// the errors to show next to each field.
export function buildMapping(fields: JiraField[], draft: Draft, t: TFunction): { mapping: Record<string, MappingSpec | null>; errors: Record<string, string> } {
  const mapping: Record<string, MappingSpec | null> = {}
  const errors: Record<string, string> = {}
  for (const field of fields) {
    if (!field.fillable) {
      if (mustFill(field) && field.type !== 'managed') errors[field.id] = t('jira.mapping.required_unsupported')
      continue
    }
    const spec = specOf(field, draft[field.id] ?? EMPTY)
    if (spec === 'incomplete') errors[field.id] = mustFill(field) ? t('jira.mapping.required') : t('jira.mapping.incomplete')
    else if (spec === 'number') errors[field.id] = t('jira.mapping.number')
    else if (spec === null && mustFill(field)) errors[field.id] = t('jira.mapping.required')
    else mapping[field.id] = spec
  }
  return { mapping, errors }
}
