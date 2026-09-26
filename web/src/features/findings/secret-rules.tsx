import { useCallback, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, Plus, Trash2, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { ApiError } from '@/shared/api/http'
import type { PostBody, Response } from '@/shared/api/client'
import { secretBuiltinRulesQuery } from '@/shared/api/queries'
import { formatDate } from '@/shared/lib/types'

export type SecretConfig = Response<'/api/secrets/config'>
export type SecretBody = PostBody<'/api/secrets/config'>
type RuleDraft = { key: number; id: string; description: string; regex: string; keywords: string }
type Form = { regexes: string; paths: string; stopwords: string; rules: RuleDraft[]; disabled: string[]; reason: string }
type Problem = { field?: string; message: string }

const LISTS = ['regexes', 'paths', 'stopwords'] as const
const LIST_LABEL = { regexes: 'secret_rules.allow_regexes', paths: 'secret_rules.allow_paths', stopwords: 'secret_rules.allow_stopwords' } as const
const LIST_HELP = { regexes: 'secret_rules.allow_regexes_help', paths: 'secret_rules.allow_paths_help', stopwords: 'secret_rules.allow_stopwords_help' } as const
const CHANGE_LABEL: Record<string, string> = {
  'regexes.added': 'secret_rules.changes.regexes_added', 'regexes.removed': 'secret_rules.changes.regexes_removed',
  'paths.added': 'secret_rules.changes.paths_added', 'paths.removed': 'secret_rules.changes.paths_removed',
  'stopwords.added': 'secret_rules.changes.stopwords_added', 'stopwords.removed': 'secret_rules.changes.stopwords_removed',
  'rules.added': 'secret_rules.changes.rules_added', 'rules.removed': 'secret_rules.changes.rules_removed', 'rules.changed': 'secret_rules.changes.rules_changed',
  'disabled_rules.added': 'secret_rules.changes.disabled_added', 'disabled_rules.removed': 'secret_rules.changes.disabled_removed',
}
// Fields the form can point at; any other server error is shown above the buttons.
const KNOWN_FIELD = /^(allowlist\.(regexes|paths|stopwords)|rules\.\d+\.(id|description|regex|keywords)|disabled_rules|reason)(\.|$)/
const area = 'w-full rounded-lg border border-app-line bg-app px-3 py-2 font-mono text-xs leading-5 text-app-fg aria-invalid:border-danger-line'

let nextKey = 0
const lines = (value: string) => value.split('\n').map(line => line.trim()).filter(Boolean)

function toForm(config: SecretConfig): Form {
  return { regexes: config.allowlist.regexes.join('\n'), paths: config.allowlist.paths.join('\n'), stopwords: config.allowlist.stopwords.join('\n'),
    rules: config.rules.map(rule => ({ id: rule.id, description: rule.description, regex: rule.regex, keywords: rule.keywords.join(', '), key: nextKey++ })), disabled: [...config.disabled_rules], reason: '' }
}

function toBody(form: Form): SecretBody {
  return { allowlist: { regexes: lines(form.regexes), paths: lines(form.paths), stopwords: lines(form.stopwords) },
    rules: form.rules.map(rule => ({ id: rule.id.trim(), description: rule.description.trim(), regex: rule.regex.trim(),
      keywords: rule.keywords.split(',').map(word => word.trim()).filter(Boolean) })),
    disabled_rules: form.disabled, reason: form.reason.trim() }
}

// Secret detection settings (the defaults or one repository's own entries) in a dialog: the form for an admin, a
// read-only view (without the patterns) for everyone else, and the history of changes.
export function SecretRulesDialog<C extends SecretConfig>({ open, onOpenChange, title, description, config, canEdit, save, onSaved, children }: {
  open: boolean; onOpenChange: (open: boolean) => void; title: string; description: string; config: C; canEdit: boolean
  save: (body: SecretBody) => Promise<C>; onSaved: (saved: C) => void; children?: ReactNode
}) {
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent className="max-w-3xl">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      {children}
      {open && (canEdit
        ? <SecretRulesForm config={config} save={save} onCancel={() => onOpenChange(false)} onSaved={onSaved} />
        : <SecretRulesView config={config} />)}
      <History entries={config.history} />
    </DialogContent>
  </Dialog>
}

function Section({ title, help, children }: { title: string; help?: string; children: ReactNode }) {
  return <section className="space-y-2">
    <div><h3 className="text-sm font-semibold text-app-secondary">{title}</h3>{help && <p className="text-xs leading-5 text-app-subtle">{help}</p>}</div>
    {children}
  </section>
}

function Chips({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-xs text-app-subtle">{empty}</p>
  return <p className="flex flex-wrap gap-1.5">{items.map(item => <code key={item} className="rounded border border-app-line bg-app px-1.5 py-0.5 font-mono text-xs break-all">{item}</code>)}</p>
}

function SecretRulesView({ config }: { config: SecretConfig }) {
  const { t } = useTranslation('findings')
  const none = t('secret_rules.none')
  return <div className="space-y-5">
    <Section title={t('secret_rules.custom_rules')} help={t('secret_rules.custom_rules_help')}>
      {config.rules.length ? <ul className="space-y-2">{config.rules.map(rule => <li key={rule.id} className="rounded-lg border border-app-line bg-app px-3 py-2">
        <p className="flex flex-wrap items-baseline gap-x-2 text-sm"><span className="font-medium text-app-secondary">{rule.description}</span>
          <span className="text-xs text-app-muted">{rule.id}</span></p>
        <code className="mt-1 block font-mono text-xs break-all text-app-muted">{rule.regex}</code>
        {rule.keywords.length ? <p className="mt-1 text-xs text-app-subtle">{t('secret_rules.keywords_list', { keywords: rule.keywords.join(', ') })}</p> : null}
      </li>)}</ul> : <p className="text-xs text-app-subtle">{none}</p>}
    </Section>
    <Section title={t('secret_rules.disabled')} help={t('secret_rules.disabled_help')}><Chips items={config.disabled_rules} empty={none} /></Section>
    {LISTS.map(name => <Section key={name} title={t(LIST_LABEL[name])} help={t(LIST_HELP[name])}><Chips items={config.allowlist[name]} empty={none} /></Section>)}
  </div>
}

function SecretRulesForm<C extends SecretConfig>({ config, save: submit, onSaved, onCancel }: {
  config: C; save: (body: SecretBody) => Promise<C>; onSaved: (saved: C) => void; onCancel: () => void
}) {
  const { t } = useTranslation('findings')
  const id = useId()
  const catalogQuery = useQuery(secretBuiltinRulesQuery())
  const catalog = catalogQuery.data
  const builtin = useMemo(() => catalog?.rules ?? [], [catalog])
  const [form, setForm] = useState<Form>(() => toForm(config))
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const limits = config.limits

  const set = (patch: Partial<Form>) => setForm(current => ({ ...current, ...patch }))
  const setRule = (key: number, patch: Partial<RuleDraft>) => setForm(current => ({ ...current, rules: current.rules.map(rule => rule.key === key ? { ...rule, ...patch } : rule) }))
  const errorFor = (prefix: string) => problem?.field && (problem.field === prefix || problem.field.startsWith(`${prefix}.`)) ? problem.message : null
  const disabled = form.disabled
  const search = useCallback(async (query: string) => {
    const needle = query.toLowerCase()
    const matches = builtin.filter(rule => !disabled.includes(rule.id) && rule.id.includes(needle))
    return { total: matches.length, options: matches.slice(0, 30).map(rule => ({ id: rule.id, label: rule.id,
      hint: rule.trivy ? t('secret_rules.trivy_too') : t('secret_rules.gitleaks_only') })) }
  }, [builtin, disabled, t])

  // The control an error points at: it gets the focus (and the scroll) so the reason is in view, not above the fold.
  const targetOf = (field?: string) => {
    const rule = field ? /^rules\.(\d+)\.(id|description|regex|keywords)/.exec(field) : null
    if (rule) return form.rules[Number(rule[1])] ? `${id}-rule-${form.rules[Number(rule[1])].key}-${rule[2]}` : null
    const list = field ? /^allowlist\.(regexes|paths|stopwords)/.exec(field) : null
    if (list) return `${id}-${list[1]}`
    return field === 'reason' ? `${id}-reason` : field?.startsWith('disabled_rules') ? `${id}-disabled-error` : null
  }
  const report = (next: Problem) => {
    setProblem(next)
    const target = targetOf(next.field)
    if (target) window.setTimeout(() => { const element = document.getElementById(target); element?.scrollIntoView({ block: 'center' }); element?.focus() }, 0)
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (form.reason.trim().length < 5) { report({ field: 'reason', message: t('secret_rules.reason_required') }); return }
    setBusy(true); setProblem(null)
    try {
      onSaved(await submit(toBody(form)))
    } catch (caught) {
      report({ field: caught instanceof ApiError ? caught.field : undefined, message: caught instanceof Error ? caught.message : String(caught) })
    } finally { setBusy(false) }
  }

  const general = problem && !(problem.field && KNOWN_FIELD.test(problem.field)) ? problem.message : null
  return <form onSubmit={save} className="space-y-5" noValidate>
    <Section title={t('secret_rules.custom_rules')} help={t('secret_rules.custom_rules_help')}>
      {form.rules.map((rule, index) => {
        const base = `${id}-rule-${rule.key}`
        const fieldError = (name: string) => errorFor(`rules.${index}.${name}`)
        const input = (name: 'id' | 'description' | 'regex' | 'keywords', label: string, props: { placeholder?: string; mono?: boolean; maxLength?: number }) => {
          const error = fieldError(name)
          return <div className="space-y-1">
            <label htmlFor={`${base}-${name}`} className="text-[11px] font-medium text-app-muted">{label}</label>
            <Input id={`${base}-${name}`} value={rule[name]} onChange={event => setRule(rule.key, { [name]: event.target.value })} maxLength={props.maxLength}
              placeholder={props.placeholder} spellCheck={false} aria-invalid={!!error || undefined} aria-describedby={error ? `${base}-${name}-error` : undefined}
              className={`h-8 border-app-line bg-app ${props.mono ? 'font-mono text-xs' : ''}`} />
            {error && <p id={`${base}-${name}-error`} className="text-xs text-danger">{error}</p>}
          </div>
        }
        return <fieldset key={rule.key} className="space-y-2 rounded-lg border border-app-line bg-inset px-3 py-3">
          <legend className="sr-only">{t('secret_rules.rule_number', { number: index + 1 })}</legend>
          <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
            {input('id', t('secret_rules.rule_id'), { placeholder: 'acme-api-token', maxLength: 60 })}
            <Button type="button" size="icon-sm" variant="ghost" onClick={() => set({ rules: form.rules.filter(item => item.key !== rule.key) })}
              aria-label={t('secret_rules.remove_rule', { id: rule.id || index + 1 })} title={t('secret_rules.remove_rule', { id: rule.id || index + 1 })}><Trash2 /></Button>
          </div>
          {input('description', t('secret_rules.description'), { placeholder: t('secret_rules.description_placeholder'), maxLength: limits.description })}
          {input('regex', t('secret_rules.regex'), { placeholder: 'acme_[0-9a-f]{32}', mono: true, maxLength: limits.regex })}
          {input('keywords', t('secret_rules.keywords'), { placeholder: 'acme_', mono: true })}
        </fieldset>
      })}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" size="sm" variant="outline" disabled={form.rules.length >= limits.rules}
          onClick={() => set({ rules: [...form.rules, { key: nextKey++, id: '', description: '', regex: '', keywords: '' }] })}><Plus />{t('secret_rules.add_rule')}</Button>
        <span className="text-xs text-app-subtle">{t('secret_rules.rules_limit', { count: form.rules.length, max: limits.rules })}</span>
      </div>
    </Section>

    <Section title={t('secret_rules.disabled')} help={t('secret_rules.disabled_help')}>
      <Combobox label={t('secret_rules.disable_label')} placeholder={t('secret_rules.disable_placeholder')} value={null} search={search}
        emptyText={catalogQuery.isError ? t('secret_rules.builtin_failed') : catalog ? t('secret_rules.no_builtin_match') : t('common:state.loading')} onSelect={(option: ComboOption) => set({ disabled: [...form.disabled, option.id].sort() })} />
      {form.disabled.length > 0 && <ul className="flex flex-wrap gap-1.5">{form.disabled.map(rule => <li key={rule} className="flex items-center gap-1 rounded border border-app-line bg-app py-0.5 pr-0.5 pl-1.5 font-mono text-xs">
        {rule}<Button type="button" size="icon-xs" variant="ghost" aria-label={t('secret_rules.enable_rule', { rule })} title={t('secret_rules.enable_rule', { rule })}
          onClick={() => set({ disabled: form.disabled.filter(item => item !== rule) })}><X /></Button></li>)}</ul>}
      {errorFor('disabled_rules') && <p id={`${id}-disabled-error`} tabIndex={-1} className="text-xs text-danger">{errorFor('disabled_rules')}</p>}
    </Section>

    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-app-secondary">{t('secret_rules.allowlist')}</h3>
      {LISTS.map(name => {
        const error = errorFor(`allowlist.${name}`)
        return <div key={name} className="space-y-1">
          <label htmlFor={`${id}-${name}`} className="text-[11px] font-medium text-app-muted">{t(LIST_LABEL[name])}</label>
          <p id={`${id}-${name}-help`} className="text-xs leading-5 text-app-subtle">{t(LIST_HELP[name], { max: limits.entries })}</p>
          <textarea id={`${id}-${name}`} value={form[name]} onChange={event => set({ [name]: event.target.value })} rows={3} spellCheck={false}
            aria-invalid={!!error || undefined} aria-describedby={`${id}-${name}-help${error ? ` ${id}-${name}-error` : ''}`} className={area} />
          {error && <p id={`${id}-${name}-error`} className="text-xs text-danger">{error}</p>}
        </div>
      })}
    </div>

    <div className="space-y-1">
      <label htmlFor={`${id}-reason`} className="text-[11px] font-medium text-app-muted">{t('secret_rules.reason')}</label>
      <Input id={`${id}-reason`} value={form.reason} onChange={event => set({ reason: event.target.value })} maxLength={300} placeholder={t('secret_rules.reason_placeholder')}
        aria-invalid={!!errorFor('reason') || undefined} aria-describedby={errorFor('reason') ? `${id}-reason-error` : undefined} className="h-9 border-app-line bg-app" />
      {errorFor('reason') && <p id={`${id}-reason-error`} className="text-xs text-danger">{errorFor('reason')}</p>}
    </div>
    <p className="text-xs leading-5 text-app-subtle">{t('secret_rules.effect')}</p>
    {general && <p role="alert" className="text-xs text-danger">{general}</p>}
    <DialogFooter>
      <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>{t('common:actions.cancel')}</Button>
      <Button type="submit" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
    </DialogFooter>
  </form>
}

function History({ entries }: { entries: SecretConfig['history'] }) {
  const { t } = useTranslation('findings')
  if (!entries.length) return null
  return <details className="rounded-lg border border-app-line bg-inset px-3 py-2">
    <summary className="cursor-pointer text-sm font-medium text-app-secondary">{t('secret_rules.history', { count: entries.length })}</summary>
    <ol className="mt-2 space-y-2">{entries.map(entry => <li key={`${entry.at}-${entry.by}`} className="text-xs leading-5">
      <p className="text-app-muted">{t('secret_rules.history_entry', { date: formatDate(entry.at), by: entry.by })}</p>
      {entry.reason && <p className="text-app-secondary">{entry.reason}</p>}
      {Object.entries(entry.changes ?? {}).flatMap(([section, kinds]) => Object.entries(kinds).map(([kind, items]) => {
        const label = CHANGE_LABEL[`${section}.${kind}`]
        return label ? <p key={`${section}.${kind}`} className="break-all text-app-subtle">{t(label, { items: items.join(', ') })}</p> : null
      }))}
    </li>)}</ol>
  </details>
}
