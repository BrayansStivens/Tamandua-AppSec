import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Check, ChevronsUpDown, LoaderCircle, Search } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export type ComboOption = { id: string; label: string; hint?: string; badge?: ReactNode }

// Buscador con autocompletado. Busca en el servidor mientras se escribe (con pausa de 200 ms),
// así escala a miles de repositorios o ejecuciones sin cargarlos todos en el navegador.
// `minChars`: nothing is searched until that many characters are typed (for lists too long to browse).
export function Combobox({ value, placeholder, search, onSelect, label, emptyText, className = '', delay = 200, minChars = 0, invalid = false, describedBy }: {
  value: ComboOption | null; placeholder: string; label: string; emptyText?: string; className?: string
  search: (query: string) => Promise<{ options: ComboOption[]; total: number }>; onSelect: (option: ComboOption) => void
  delay?: number; minChars?: number; invalid?: boolean; describedBy?: string
}) {
  const { t } = useTranslation('ui')
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [options, setOptions] = useState<ComboOption[]>([])
  const [total, setTotal] = useState(0)
  const [active, setActive] = useState(0)
  const [loading, setLoading] = useState(false)
  const [failed, setFailed] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const listId = useId()

  useEffect(() => {
    if (!open) return
    let cancelled = false
    const text = query.trim()
    const short = text.length < minChars
    const timer = window.setTimeout(() => {
      if (short) { setOptions([]); setTotal(0); setFailed(false); setLoading(false); return }
      setLoading(true)
      search(text).then(result => { if (!cancelled) { setOptions(result.options); setTotal(result.total); setActive(0); setFailed(false) } })
        .catch(() => { if (!cancelled) { setOptions([]); setTotal(0); setFailed(true) } }).finally(() => { if (!cancelled) setLoading(false) })
    }, short ? 0 : delay)
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [open, query, search, delay, minChars])
  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent) => { if (box.current && !box.current.contains(event.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  // Closing from the keyboard or by choosing returns the focus to the button, not to the page.
  const close = () => { setOpen(false); window.setTimeout(() => trigger.current?.focus(), 0) }
  const choose = (option: ComboOption) => { onSelect(option); setQuery(''); close() }
  const keys = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); setActive(index => Math.min(index + 1, options.length - 1)) }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(index => Math.max(index - 1, 0)) }
    else if (event.key === 'Enter' && options[active]) { event.preventDefault(); choose(options[active]) }
    else if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close() }
  }

  return <div ref={box} className={`relative ${className}`}>
    {!open ? <button ref={trigger} type="button" aria-label={`${label}: ${value?.label ?? placeholder}`} aria-haspopup="listbox" aria-invalid={invalid || undefined} aria-describedby={describedBy} onClick={() => { setOpen(true); window.setTimeout(() => input.current?.focus(), 0) }}
      className="flex h-9 w-full items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 text-left text-sm hover:border-brand/40">
      <span className={`min-w-0 flex-1 truncate ${value ? '' : 'text-app-subtle'}`}>{value?.label ?? placeholder}</span>
      {value?.hint && <span className="hidden shrink-0 text-xs text-app-subtle sm:inline">{value.hint}</span>}
      <ChevronsUpDown className="size-3.5 shrink-0 text-app-subtle" />
    </button>
      : <div className="flex h-9 items-center gap-2 rounded-lg border border-brand/50 bg-app-soft px-3"><Search className="size-3.5 text-app-subtle" />
        <input ref={input} role="combobox" aria-label={label} aria-invalid={invalid || undefined} aria-describedby={describedBy} aria-expanded aria-controls={listId} aria-autocomplete="list" aria-activedescendant={options[active] ? `${listId}-${active}` : undefined} value={query} onChange={event => setQuery(event.target.value)} onKeyDown={keys}
          placeholder={t('combobox.placeholder')} className="min-w-0 flex-1 bg-transparent text-sm outline-none" />{loading && <LoaderCircle className="size-3.5 text-app-subtle motion-safe:animate-spin" />}</div>}
    {open && <div className="absolute z-30 mt-1 max-h-80 w-full overflow-y-auto rounded-lg border border-app-line bg-panel p-1 shadow-xl"><ul id={listId} role="listbox" aria-label={label}>
      {options.map((option, index) => <li key={option.id} id={`${listId}-${index}`} role="option" aria-selected={value?.id === option.id} onMouseEnter={() => setActive(index)} onMouseDown={event => { event.preventDefault(); choose(option) }}
        className={`flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-2 text-sm ${index === active ? 'bg-app-soft' : ''}`}>
        <Check className={`size-3.5 shrink-0 ${value?.id === option.id ? 'text-brand' : 'text-transparent'}`} />
        <span className="min-w-0 flex-1"><span className="block truncate">{option.label}</span>{option.hint && <span className="block truncate text-xs text-app-subtle">{option.hint}</span>}</span>
        {option.badge}
      </li>)}
    </ul>
      {/* Outside the listbox, in a live region: screen readers hear why there is nothing to pick, or how many more there are. */}
      <p role="status" className="empty:hidden">{!loading && options.length === 0 ? <span className={`block px-3 py-3 text-sm ${failed ? 'text-danger' : 'text-app-subtle'}`}>{failed ? t('combobox.error')
        : query.trim().length < minChars ? t('combobox.min_chars', { count: minChars }) : emptyText ?? t('combobox.empty')}</span>
        : total > options.length ? <span className="block px-3 py-2 text-xs text-app-subtle">{t('combobox.more', { remaining: total - options.length })}</span> : null}</p>
    </div>}
  </div>
}
