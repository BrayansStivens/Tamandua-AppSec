import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Check, ChevronsUpDown, LoaderCircle, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export type ComboOption = { id: string; label: string; hint?: string; badge?: ReactNode }

// Buscador con autocompletado. Busca en el servidor mientras se escribe (con pausa de 200 ms),
// así escala a miles de repositorios o ejecuciones sin cargarlos todos en el navegador.
export function Combobox({ value, placeholder, search, onSelect, label, emptyText, className = '' }: {
  value: ComboOption | null; placeholder: string; label: string; emptyText?: string; className?: string
  search: (query: string) => Promise<{ options: ComboOption[]; total: number }>; onSelect: (option: ComboOption) => void
}) {
  const { t } = useTranslation('ui')
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [options, setOptions] = useState<ComboOption[]>([])
  const [total, setTotal] = useState(0)
  const [active, setActive] = useState(0)
  const [loading, setLoading] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const listId = useId()

  useEffect(() => {
    if (!open) return
    let cancelled = false
    setLoading(true)
    const timer = window.setTimeout(() => {
      search(query.trim()).then(result => { if (!cancelled) { setOptions(result.options); setTotal(result.total); setActive(0) } })
        .catch(() => { if (!cancelled) { setOptions([]); setTotal(0) } }).finally(() => { if (!cancelled) setLoading(false) })
    }, 200)
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [open, query, search])
  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent) => { if (box.current && !box.current.contains(event.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  const choose = (option: ComboOption) => { onSelect(option); setOpen(false); setQuery('') }
  const keys = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); setActive(index => Math.min(index + 1, options.length - 1)) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(index => Math.max(index - 1, 0)) }
    else if (event.key === 'Enter' && options[active]) { event.preventDefault(); choose(options[active]) }
    else if (event.key === 'Escape') setOpen(false)
  }

  return <div ref={box} className={`relative ${className}`}>
    {!open ? <button type="button" aria-label={`${label}: ${value?.label ?? placeholder}`} aria-haspopup="listbox" onClick={() => { setOpen(true); window.setTimeout(() => input.current?.focus(), 0) }}
      className="flex h-9 w-full items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 text-left text-sm hover:border-brand/40">
      <span className={`min-w-0 flex-1 truncate ${value ? '' : 'text-app-subtle'}`}>{value?.label ?? placeholder}</span>
      {value?.hint && <span className="hidden shrink-0 text-xs text-app-subtle sm:inline">{value.hint}</span>}
      <ChevronsUpDown className="size-3.5 shrink-0 text-app-subtle" />
    </button>
      : <div className="flex h-9 items-center gap-2 rounded-lg border border-brand/50 bg-app-soft px-3"><Search className="size-3.5 text-app-subtle" />
        <input ref={input} role="combobox" aria-label={label} aria-expanded aria-controls={listId} aria-autocomplete="list" aria-activedescendant={options[active] ? `${listId}-${active}` : undefined} value={query} onChange={event => setQuery(event.target.value)} onKeyDown={keys}
          placeholder={t('combobox.placeholder')} className="min-w-0 flex-1 bg-transparent text-sm outline-none" />{loading && <LoaderCircle className="size-3.5 animate-spin text-app-subtle" />}</div>}
    {open && <ul id={listId} role="listbox" className="absolute z-30 mt-1 max-h-80 w-full overflow-y-auto rounded-lg border border-app-line bg-panel p-1 shadow-xl">
      {options.map((option, index) => <li key={option.id} id={`${listId}-${index}`} role="option" aria-selected={value?.id === option.id} onMouseEnter={() => setActive(index)} onMouseDown={event => { event.preventDefault(); choose(option) }}
        className={`flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-2 text-sm ${index === active ? 'bg-app-soft' : ''}`}>
        <Check className={`size-3.5 shrink-0 ${value?.id === option.id ? 'text-brand' : 'text-transparent'}`} />
        <span className="min-w-0 flex-1"><span className="block truncate">{option.label}</span>{option.hint && <span className="block truncate text-xs text-app-subtle">{option.hint}</span>}</span>
        {option.badge}
      </li>)}
      {!loading && options.length === 0 && <li className="px-3 py-3 text-sm text-app-subtle">{emptyText ?? t('combobox.empty')}</li>}
      {total > options.length && <li className="px-3 py-2 text-xs text-app-subtle">{t('combobox.more', { remaining: total - options.length })}</li>}
    </ul>}
  </div>
}
