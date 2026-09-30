import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, ArrowRight, CircleCheck, FileUp, LoaderCircle, SlidersHorizontal } from 'lucide-react'
import { apiPost, type PostBody } from '@/shared/api/client'
import { ApiError } from '@/shared/api/http'
import { keys } from '@/shared/api/queries'
import type { components } from '@/shared/api/schema'
import { formatList, formatNumber } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { AssetPicker, type Asset } from '@/features/sources/asset-picker'
import { validBranch } from '@/features/sources/sources'

// Same cap as the server (tamandua/modules/scanning/sarif_import.py MAX_BYTES).
export const SARIF_MAX_BYTES = 10_000_000
const MAX_MB = SARIF_MAX_BYTES / 1_000_000
const COMMIT = /^[0-9a-f]{7,64}$/i

type Body = PostBody<'/api/imports/sarif'>
type Result = components['schemas']['SarifImportResult']
type Picked = { name: string; size: number; sarif: Body['sarif']; tools: string[]; results: number }
type Scope = 'full' | 'partial'

const record = (value: unknown): Record<string, unknown> | null => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
const fileSize = (bytes: number) => bytes < 1_000_000
  ? formatNumber(Math.max(1, bytes / 1000), { style: 'unit', unit: 'kilobyte', maximumFractionDigits: 0 })
  : formatNumber(bytes / 1_000_000, { style: 'unit', unit: 'megabyte', maximumFractionDigits: 1 })

// Findings from another tool into an asset Tamandua already knows; one run per tool in the file.
export function SarifImport({ onOpenRun, onBack }: { onOpenRun: (id: string) => void | Promise<void>; onBack: () => void }) {
  const { t } = useTranslation('analyses')
  const id = useId()
  const queryClient = useQueryClient()
  const [asset, setAsset] = useState<Asset | null>(null)
  const [assets, setAssets] = useState<number | 'error' | null>(null)
  const loaded = useCallback((total: number | 'error') => setAssets(total), [])
  const [picked, setPicked] = useState<Picked | null>(null)
  const [fileError, setFileError] = useState('')
  const [reading, setReading] = useState(false)
  const [scope, setScope] = useState<Scope>('full')
  const [more, setMore] = useState(false)
  const [tool, setTool] = useState('')
  const [commit, setCommit] = useState('')
  const [branch, setBranch] = useState('')
  const mutation = useMutation({
    mutationFn: (body: Body) => apiPost('/api/imports/sarif', 'import-sarif', body),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: keys.runs }) },
  })

  const commitInvalid = !!commit.trim() && !COMMIT.test(commit.trim())
  const branchInvalid = !!branch.trim() && !validBranch(branch.trim())
  const ready = !!asset && !!picked && !reading && !commitInvalid && !branchInvalid && !mutation.isPending

  // Read and checked here: a file that is too big or isn't JSON never leaves the browser.
  const read = async (file: File | undefined) => {
    setPicked(null); setFileError(''); mutation.reset()
    if (!file) return
    if (file.size > SARIF_MAX_BYTES) { setFileError(t('import.file.too_large', { name: file.name, size: fileSize(file.size), max: MAX_MB })); return }
    setReading(true)
    try {
      let parsed: unknown
      try { parsed = JSON.parse(await file.text()) } catch { setFileError(t('import.file.invalid_json', { name: file.name })); return }
      const document = record(parsed)
      const runs = Array.isArray(document?.runs) ? document.runs.map(record) : []
      if (!document || !runs.length) { setFileError(t('import.file.not_sarif', { name: file.name })); return }
      const tools = [...new Set(runs.map(run => record(record(run?.tool)?.driver)?.name).filter((name): name is string => typeof name === 'string' && !!name.trim()))]
      const results = runs.reduce((total, run) => total + (Array.isArray(run?.results) ? run.results.length : 0), 0)
      setPicked({ name: file.name, size: file.size, sarif: document, tools, results })
    } finally { setReading(false) }
  }

  const submit = () => {
    if (!ready || !asset || !picked) return
    mutation.mutate({ asset: asset.key, scope, sarif: picked.sarif, ...(tool.trim() ? { tool: tool.trim() } : {}),
      ...(commit.trim() ? { commit: commit.trim() } : {}), ...(branch.trim() ? { branch: branch.trim() } : {}) })
  }
  const failure = mutation.error
  // The server explains every refusal; only a proxy cutting the body off answers 413 without a message.
  const failureText = failure instanceof ApiError && failure.status === 413 && failure.message === `Error ${failure.status}`
    ? t('import.too_large', { max: MAX_MB }) : failure instanceof Error ? failure.message : failure ? String(failure) : ''

  if (mutation.data) return <ImportResult result={mutation.data} scope={scope} onOpenRun={onOpenRun}
    onAnother={() => { mutation.reset(); setPicked(null) }} onBack={onBack} />

  return <div className="space-y-6">
    <Button variant="ghost" onClick={onBack}><ArrowLeft /> {t('wizard.back_to_types')}</Button>
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('import.title')}</CardTitle><CardDescription>{t('import.description')}</CardDescription></CardHeader><CardContent className="space-y-5">
      <div className="max-w-xl space-y-1.5"><span aria-hidden className="text-sm text-app-secondary">{t('import.asset')}</span>
        <AssetPicker value={asset} onChange={setAsset} onLoaded={loaded} label={t('import.asset')} placeholder={t('findings:page.asset_placeholder')} />
        {assets === 0 && <p className="text-xs text-app-muted">{t('import.no_asset')}</p>}
        {assets === 'error' && <p role="alert" className="text-xs text-danger">{t('import.asset_error')}</p>}</div>

      <div className="space-y-1.5">
        <label htmlFor={`${id}-file`} className="text-sm text-app-secondary">{t('import.file.label')} <span className="text-app-subtle">{t('import.file.hint', { max: MAX_MB })}</span></label>
        <input id={`${id}-file`} type="file" accept=".sarif,.json,application/json,application/sarif+json" aria-invalid={!!fileError} aria-describedby={`${id}-file-help`}
          onChange={event => void read(event.target.files?.[0])}
          className="block w-full max-w-xl rounded-xl border border-app-line bg-app-soft p-2 text-sm text-app-secondary file:mr-3 file:min-h-6 file:rounded-lg file:border-0 file:bg-brand/15 file:px-3 file:py-1 file:text-sm file:font-medium file:text-brand" />
        <div id={`${id}-file-help`}>
          {fileError ? <p role="alert" className="text-xs text-danger">{fileError}</p>
            : reading ? <p role="status" className="text-xs text-app-muted">{t('common:state.loading')}</p>
            : picked ? <p role="status" className="text-xs text-app-muted">{t('import.file.summary', { count: picked.results, name: picked.name, size: fileSize(picked.size), tools: picked.tools.length ? formatList(picked.tools) : t('import.file.unknown_tool') })}</p>
            : null}
        </div>
      </div>

      <div className="space-y-2">
        <span id={`${id}-scope`} className="text-sm text-app-secondary">{t('import.scope.label')}</span>
        <div role="radiogroup" aria-labelledby={`${id}-scope`} className="grid gap-2 sm:grid-cols-2">
          {([['full', t('import.scope.full'), t('import.scope.full_hint')], ['partial', t('import.scope.partial'), t('import.scope.partial_hint')]] as const).map(([value, title, hint]) =>
            <label key={value} className={`flex cursor-pointer flex-col gap-0.5 rounded-xl border p-3 text-sm ${scope === value ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset'}`}>
              <span className="flex items-center gap-2"><input type="radio" name={`${id}-scope`} value={value} checked={scope === value} onChange={() => setScope(value)} className="size-4 accent-brand" /><span className="font-medium">{title}</span></span>
              <span className="pl-6 text-xs text-app-muted">{hint}</span></label>)}
        </div>
        <p className="text-xs text-app-subtle">{t('import.scope.note')}</p>
      </div>

      <div className="space-y-3">
        <Button type="button" size="sm" variant="outline" aria-expanded={more} aria-controls={`${id}-more`} onClick={() => setMore(!more)} className="w-fit border-app-line bg-app-soft"><SlidersHorizontal />{t('import.more')}</Button>
        {more && <div id={`${id}-more`} className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1"><label htmlFor={`${id}-tool`} className="text-xs text-app-secondary">{t('import.tool')} <span className="text-app-subtle">{t('import.optional')}</span></label>
            <Input id={`${id}-tool`} value={tool} maxLength={100} onChange={event => setTool(event.target.value)} placeholder={picked?.tools[0] ?? ''} className="border-app-line bg-app-soft" />
            <p className="text-[11px] text-app-subtle">{t('import.tool_hint')}</p></div>
          <div className="space-y-1"><label htmlFor={`${id}-commit`} className="text-xs text-app-secondary">{t('import.commit')} <span className="text-app-subtle">{t('import.optional')}</span></label>
            <Input id={`${id}-commit`} value={commit} maxLength={64} spellCheck={false} autoComplete="off" aria-invalid={commitInvalid} aria-describedby={commitInvalid ? `${id}-commit-error` : undefined} onChange={event => setCommit(event.target.value)} className="border-app-line bg-app-soft font-mono" />
            {commitInvalid && <p id={`${id}-commit-error`} className="text-[11px] text-danger">{t('import.commit_invalid')}</p>}</div>
          <div className="space-y-1"><label htmlFor={`${id}-branch`} className="text-xs text-app-secondary">{t('import.branch')} <span className="text-app-subtle">{t('import.optional')}</span></label>
            <Input id={`${id}-branch`} value={branch} maxLength={200} spellCheck={false} autoComplete="off" aria-invalid={branchInvalid} aria-describedby={branchInvalid ? `${id}-branch-error` : undefined} onChange={event => setBranch(event.target.value)} className="border-app-line bg-app-soft font-mono" />
            {branchInvalid && <p id={`${id}-branch-error`} className="text-[11px] text-danger">{t('import.branch_invalid')}</p>}</div>
        </div>}
      </div>

      {failureText && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{failureText}</p>}
    </CardContent></Card>

    <div className="flex items-center justify-between gap-3 border-t border-app-line pt-5">
      <Button variant="ghost" onClick={onBack}><ArrowLeft /> {t('wizard.back')}</Button>
      <Button onClick={submit} disabled={!ready} className="bg-primary text-primary-foreground hover:bg-primary/90">{mutation.isPending ? <LoaderCircle className="motion-safe:animate-spin" /> : <FileUp />}{mutation.isPending ? t('import.submitting') : t('import.submit')}</Button>
    </div>
  </div>
}

function ImportResult({ result, scope, onOpenRun, onAnother, onBack }: { result: Result; scope: Scope; onOpenRun: (id: string) => void | Promise<void>; onAnother: () => void; onBack: () => void }) {
  const { t } = useTranslation('analyses')
  // The form that had focus is gone: the outcome takes it, so screen readers hear it and the keyboard doesn't fall to <body>.
  const title = useRef<HTMLHeadingElement>(null)
  useEffect(() => { title.current?.focus() }, [])
  const single = result.runs.length === 1
  return <div className="space-y-6">
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle ref={title} tabIndex={-1} className="flex items-center gap-2"><CircleCheck className="size-5 text-success" />{t('import.result.title', { name: result.name })}</CardTitle><CardDescription>{scope === 'full' ? t('import.result.description_full') : t('import.result.description_partial')}</CardDescription></CardHeader>
      <CardContent><ul className="space-y-2">{result.runs.map(run => <li key={run.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-app-line bg-inset p-3">
        <span className="min-w-0"><span className="block truncate text-sm font-medium">{run.tool}{run.version ? <span className="font-normal text-app-subtle"> {run.version}</span> : null}</span>
          <span className="text-xs text-app-muted">{[t('import.result.findings', { count: run.findings }), t('import.result.opened', { count: run.opened }),
            ...(run.scope === 'full' ? [t('import.result.fixed', { count: run.fixed })] : []), ...(run.skipped ? [t('import.result.skipped', { count: run.skipped })] : [])].join(' · ')}</span></span>
        <Button variant={single ? 'default' : 'outline'} size="sm" aria-label={t('import.result.open_label', { tool: run.tool })} onClick={() => void onOpenRun(run.id)} className={single ? 'bg-primary text-primary-foreground hover:bg-primary/90' : 'border-app-line bg-panel'}>{t('import.result.open')} <ArrowRight /></Button>
      </li>)}</ul></CardContent></Card>
    <div className="flex items-center justify-between gap-3 border-t border-app-line pt-5">
      <Button variant="ghost" onClick={onBack}><ArrowLeft /> {t('wizard.back_to_types')}</Button>
      <Button variant="outline" onClick={onAnother} className="border-app-line bg-app-soft"><FileUp />{t('import.result.another')}</Button>
    </div>
  </div>
}
