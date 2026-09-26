import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/shared/ui/button'

// Una pestaña abierta sigue ejecutando el panel que cargó aunque el servidor se haya actualizado.
// Al volver a la pestaña (y cada 5 minutos) se compara el paquete publicado con el que corre aquí.
const bundle = (html: string) => html.match(/\/assets\/index-[A-Za-z0-9_-]+\.js/)?.[0] ?? null

export function UpdateNotice() {
  const [stale, setStale] = useState(false)
  useEffect(() => {
    const running = bundle(document.documentElement.outerHTML)
    if (!running) return
    const check = async () => {
      try {
        const published = bundle(await (await fetch('/', { cache: 'no-store', credentials: 'same-origin' })).text())
        if (published && published !== running) setStale(true)
      } catch { /* sin conexión: se vuelve a mirar más tarde */ }
    }
    const onVisible = () => { if (document.visibilityState === 'visible') void check() }
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('focus', onVisible)
    const timer = window.setInterval(() => void check(), 5 * 60_000)
    return () => { document.removeEventListener('visibilitychange', onVisible); window.removeEventListener('focus', onVisible); window.clearInterval(timer) }
  }, [])
  if (!stale) return null
  return <div role="status" className="fixed right-4 bottom-4 z-50 flex max-w-sm items-center gap-3 rounded-xl border border-brand/40 bg-panel px-4 py-3 text-sm shadow-lg">
    <span className="text-app-secondary">Hay una versión nueva del panel. Recarga para usarla; guarda antes lo que tengas sin guardar.</span>
    <Button size="sm" onClick={() => window.location.reload()} className="shrink-0 bg-primary text-primary-foreground hover:bg-primary/90"><RefreshCw />Recargar</Button>
  </div>
}
