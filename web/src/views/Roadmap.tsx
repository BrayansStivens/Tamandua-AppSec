import { Badge } from '@/components/ui/badge'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

const milestones = [
  { week: '01', name: 'Base verificable', items: 'Panel responsive · consola acotada · ejecución del laboratorio · contratos de evidencia', status: 'En marcha' },
  { week: '02', name: 'Código y dependencias', items: 'Adaptadores SAST, SCA y secretos · ingesta normalizada · CVE ↔ CISA KEV', status: 'Siguiente' },
  { week: '03', name: 'Pruebas dinámicas', items: 'Runner aislado · alcance autorizado · DAST en staging propio · trazas y límites', status: 'Planificado' },
  { week: '04', name: 'Piloto SaaS', items: 'Prioridad por negocio · reportes consistentes · exportaciones · evaluación ciega', status: 'Planificado' },
]

export function Roadmap() {
  return <div className="grid gap-4 md:grid-cols-2">{milestones.map(item => <Card key={item.week} className="border-app-line bg-panel"><CardHeader><div className="flex items-center justify-between"><span className="font-mono text-sm text-brand">SEMANA {item.week}</span><Badge variant="outline" className="border-app-line text-app-secondary">{item.status}</Badge></div><CardTitle>{item.name}</CardTitle><CardDescription className="leading-6">{item.items}</CardDescription></CardHeader></Card>)}</div>
}
