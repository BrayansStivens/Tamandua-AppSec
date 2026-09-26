import { useEffect, useState, type ReactNode } from 'react'
import { BrandMark } from '@/shared/ui/brand-mark'
import { BRAND } from '@/shared/lib/brand'
import { LOADING_EVENT } from '@/shared/api/http'

// Pantalla de arranque: la marca en el centro, con un pulso suave mientras se comprueba la sesión.
export function Splash() {
  return <div className="grid min-h-screen place-items-center bg-app" role="status" aria-label={`Cargando ${BRAND.name}`}>
    <div className="flex animate-[tamandua-breathe_1.8s_ease-in-out_infinite] items-center gap-3 opacity-80">
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
    <div className="h-full w-1/3 motion-safe:animate-[tamandua-progress_1.1s_ease-in-out_infinite] bg-brand" />
  </div>
}

// Esqueletos de carga: la forma del contenido que viene, en lugar de un hueco o un «Cargando…».
// Accesibles (WCAG 4.1.3): un único aviso «Cargando …» para lectores de pantalla y las formas
// ocultas a la tecnología de asistencia. El pulso respeta «reducir movimiento» (2.3.3).

// Bloque base. Todas las formas salen de aquí.
export function Bone({ className = '' }: { className?: string }) {
  return <span aria-hidden className={`block rounded-md bg-skeleton motion-safe:animate-pulse ${className}`} />
}

function Region({ label, className = '', children }: { label: string; className?: string; children: ReactNode }) {
  // El diseño (grid, divide…) va en el contenedor de las formas, que es el que tiene los hijos.
  return <div role="status" aria-live="polite" aria-busy="true">
    <span className="sr-only">{label}</span>
    <div aria-hidden className={className}>{children}</div>
  </div>
}

// Lista: icono, título, línea secundaria y, si se pide, una acción al final (filas de repositorios, PRs, análisis).
export function SkeletonList({ rows = 5, label = 'Cargando', action = false, dense = false }: { rows?: number; label?: string; action?: boolean; dense?: boolean }) {
  return <Region label={label} className="divide-y divide-app-line">
    {Array.from({ length: rows }, (_, index) => <div key={index} className={`flex items-center gap-3 ${dense ? 'px-3 py-2' : 'px-4 py-3'}`}>
      <Bone className="size-4 shrink-0 rounded" />
      <div className="min-w-0 flex-1 space-y-1.5"><Bone className={`h-3.5 ${index % 3 === 0 ? 'w-2/5' : index % 3 === 1 ? 'w-1/2' : 'w-1/3'}`} />{!dense && <Bone className="h-3 w-1/4" />}</div>
      {action && <Bone className="h-8 w-20 shrink-0 rounded-lg" />}
    </div>)}
  </Region>
}

// Tabla: cabecera y filas con tantas columnas como la tabla real.
export function SkeletonTable({ rows = 6, columns = 4, label = 'Cargando' }: { rows?: number; columns?: number; label?: string }) {
  const widths = ['w-3/4', 'w-1/2', 'w-2/3', 'w-1/3', 'w-5/6']
  return <Region label={label} className="overflow-hidden rounded-xl border border-app-line">
    <div className="grid gap-3 border-b border-app-line px-4 py-3" style={{ gridTemplateColumns: `2fr repeat(${columns - 1}, minmax(0, 1fr))` }}>
      {Array.from({ length: columns }, (_, index) => <Bone key={index} className="h-3 w-16" />)}
    </div>
    {Array.from({ length: rows }, (_, row) => <div key={row} className="grid items-center gap-3 border-b border-app-line px-4 py-3 last:border-b-0" style={{ gridTemplateColumns: `2fr repeat(${columns - 1}, minmax(0, 1fr))` }}>
      {Array.from({ length: columns }, (_, column) => <Bone key={column} className={`h-3.5 ${widths[(row + column) % widths.length]}`} />)}
    </div>)}
  </Region>
}

// Métricas: tarjetas con número y etiqueta (resumen, hallazgos).
export function SkeletonTiles({ count = 4, label = 'Cargando' }: { count?: number; label?: string }) {
  return <Region label={label} className={`grid gap-3 ${count > 4 ? 'sm:grid-cols-3 xl:grid-cols-6' : 'sm:grid-cols-2 xl:grid-cols-4'}`}>
    {Array.from({ length: count }, (_, index) => <div key={index} className="space-y-3 rounded-xl border border-app-line bg-panel p-4"><Bone className="h-7 w-12" /><Bone className="h-3 w-24" /></div>)}
  </Region>
}

// Tarjeta con título, descripción y cuerpo de líneas (paneles de detalle, formularios de solo lectura).
export function SkeletonCard({ lines = 3, label = 'Cargando' }: { lines?: number; label?: string }) {
  return <Region label={label} className="space-y-4 rounded-xl border border-app-line bg-panel p-5">
    <div className="space-y-2"><Bone className="h-5 w-1/3" /><Bone className="h-3.5 w-2/3" /></div>
    <div className="space-y-2">{Array.from({ length: lines }, (_, index) => <Bone key={index} className={`h-3.5 ${index === lines - 1 ? 'w-1/2' : 'w-full'}`} />)}</div>
  </Region>
}

// Bloques genéricos (y métricas encima si se piden).
export function Skeleton({ rows = 3, tiles = 0, label = 'Cargando' }: { rows?: number; tiles?: number; label?: string }) {
  return <Region label={label} className="space-y-4">
    {tiles > 0 && <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">{Array.from({ length: tiles }, (_, index) => <Bone key={index} className="h-20 rounded-xl" />)}</div>}
    {Array.from({ length: rows }, (_, index) => <Bone key={index} className="h-14 rounded-xl" />)}
  </Region>
}
