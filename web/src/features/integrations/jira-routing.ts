import type { JiraRouting } from '@/shared/api/queries'

export type JiraRule = JiraRouting['rules'][number]
export type JiraDestination = JiraRouting['destinations'][number]
export type JiraRef = { id?: string | null; key?: string | null; name?: string | null }

// Python's fnmatchcase (what the server uses on lowercased names): *, ?, [seq] and [!seq].
export function globMatch(pattern: string, text: string): boolean {
  let source = ''
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index]
    if (char === '*') source += '.*'
    else if (char === '?') source += '.'
    else if (char === '[') {
      let end = index + 1
      if (pattern[end] === '!') end++
      if (pattern[end] === ']') end++
      while (end < pattern.length && pattern[end] !== ']') end++
      if (end >= pattern.length) { source += '\\['; continue }
      let set = pattern.slice(index + 1, end).replace(/\\/g, '\\\\')
      if (set.startsWith('!')) set = `^${set.slice(1)}`
      else if (set.startsWith('^')) set = `\\${set}`
      source += `[${set}]`
      index = end
    } else source += char.replace(/[.+^${}()|\\/]/g, '\\$&')
  }
  try { return new RegExp(`^${source}$`, 's').test(text) } catch { return false }
}

export function ruleMatches(rule: Pick<JiraRule, 'default' | 'assets' | 'patterns'>, key: string, name: string | null | undefined): boolean {
  if (rule.default) return true
  if (rule.assets.includes(key)) return true
  const lowered = (name ?? '').toLowerCase()
  return !!lowered && rule.patterns.some(pattern => globMatch(pattern.toLowerCase(), lowered))
}

// The rule that decides for an asset, as the server does: the first enabled one that matches and has a destination.
export function resolveRule(routing: Pick<JiraRouting, 'rules'>, key: string, name: string | null | undefined): JiraRule | null {
  return routing.rules.find(rule => rule.enabled && rule.destination && ruleMatches(rule, key, name)) ?? null
}

export const destinationOf = (routing: Pick<JiraRouting, 'destinations'>, id: string | null | undefined) =>
  routing.destinations.find(item => item.id === id) ?? null

// Project and issue type as Jira names them (shown raw): "SEC · Bug".
export function destinationTarget(destination: JiraDestination): string {
  const project = destination.project as JiraRef
  const issueType = destination.issue_type as JiraRef
  return [project.key ?? project.name, issueType.name].filter(Boolean).join(' · ')
}

// The API names a mapping field "mapping.<id>" (shape errors) or "<id>" (Jira's rules): both point at the same row.
const fieldOf = (field: string) => field.startsWith('mapping.') ? field.slice('mapping.'.length) : field
export const errorMap = (errors: { field: string; error: string }[] | undefined) =>
  Object.fromEntries((errors ?? []).map(item => [fieldOf(item.field), item.error]))
