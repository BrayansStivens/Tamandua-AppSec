import { useEffect, useState } from 'react'
import { BrandMark } from '@/components/brand-mark'
import { BRAND } from '@/lib/brand'
import { LOADING_EVENT } from '@/lib/api'

// Pantalla de arranque: la marca en el centro, con un pulso suave mientras se comprueba la sesión.
export function Splash() {
  return <div className="grid min-h-screen place-items-center bg-app" role="status" aria-label={`Cargando ${BRAND.name}`}>
    <div className="flex animate-[appsec-breathe_1.8s_ease-in-out_infinite] items-center gap-3 opacity-80">
      <BrandMark size={40} /><span className="text-2xl font-semibold tracking-tight text-app-fg">{BRAND.name}</span>
    </div>
  </div>
}

// Barra fina superior mientras haya peticiones en curso (tras 150 ms, para no parpadear en las rápidas).
export function TopProgress() {
  const [active, setActive] = useState(false)
  useEffect(() => {
    let timer: number | undefined
    const listen = (event: Event) => {
      const count = (event as CustomEvent<number>).detail
      window.clearTimeout(timer)
      if (count > 0) timer = window.setTimeout(() => setActive(true), 150)
      else setActive(false)
    }
    window.addEventListener(LOADING_EVENT, listen)
    return () => { window.removeEventListener(LOADING_EVENT, listen); window.clearTimeout(timer) }
  }, [])
  return <div aria-hidden className={`pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 overflow-hidden transition-opacity ${active ? 'opacity-100' : 'opacity-0'}`}>
    <div className="h-full w-1/3 animate-[appsec-progress_1.1s_ease-in-out_infinite] bg-brand" />
  </div>
}

// Esqueleto de carga: bloques con la forma del contenido que viene, en lugar de un hueco vacío.
export function Skeleton({ rows = 3, tiles = 0 }: { rows?: number; tiles?: number }) {
  return <div className="space-y-4" role="status" aria-label="Cargando">
    {tiles > 0 && <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">{Array.from({ length: tiles }, (_, index) => <div key={index} className="h-20 animate-pulse rounded-xl border border-app-line bg-app-soft" />)}</div>}
    {Array.from({ length: rows }, (_, index) => <div key={index} className="h-14 animate-pulse rounded-xl border border-app-line bg-app-soft" style={{ animationDelay: `${index * 80}ms` }} />)}
  </div>
}
