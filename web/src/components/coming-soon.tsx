import type { ReactNode } from 'react'
import { Hammer } from 'lucide-react'

// Una función que se verá pronto pero que hoy no da resultados: siempre con la misma marca y en gris.
export function SoonBadge({ className = '' }: { className?: string }) {
  return <span className={`inline-flex shrink-0 items-center gap-1 rounded-full border border-dashed border-app-faint/60 px-2 py-0.5 text-[11px] font-medium tracking-wide text-app-subtle uppercase ${className}`}>
    <Hammer className="size-3" />En desarrollo
  </span>
}

export function ComingSoonCard({ title, icon, description, plan, children }: { title: string; icon?: ReactNode; description: string; plan?: string[]; children?: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-app-line bg-inset/40 p-5 text-app-subtle">
    <div className="flex items-start justify-between gap-3">
      <div className="flex items-center gap-3 opacity-70">{icon}<h3 className="font-semibold text-app-muted">{title}</h3></div>
      <SoonBadge />
    </div>
    <p className="mt-3 text-sm leading-6 opacity-80">{description}</p>
    {plan && plan.length > 0 && <ul className="mt-3 space-y-1 text-xs leading-5 opacity-80">{plan.map(item => <li key={item} className="flex gap-2"><span aria-hidden>·</span>{item}</li>)}</ul>}
    {children}
  </div>
}

export function ComingSoonPage({ title, description, plan }: { title: string; description: string; plan: string[] }) {
  return <div className="mx-auto max-w-2xl py-6">
    <ComingSoonCard title={title} description={description} plan={plan} icon={<Hammer className="size-5" />}>
      <p className="mt-4 text-xs opacity-70">Aún no da resultados reales, por eso está desactivado. Cuando esté listo aparecerá aquí sin que tengas que hacer nada.</p>
    </ComingSoonCard>
  </div>
}
