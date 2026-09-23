import { useId } from 'react'
import { BRAND } from '@/lib/brand'

// Tamandúa (oso hormiguero de collar, nativo de Colombia) atrapando un bug con la lengua.
// Los identificadores del degradado van por instancia: hay varias marcas en la misma página.
export function BrandMark({ size = 40, className }: { size?: number; className?: string }) {
  const id = useId().replace(/:/g, '')
  return <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label={`Marca de ${BRAND.name}`} className={className}>
    <defs>
      <linearGradient id={`${id}-bg`} x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#8B5CF6" /><stop offset="1" stopColor="#5B21B6" /></linearGradient>
      <clipPath id={`${id}-clip`}><rect width="64" height="64" rx="16" /></clipPath>
    </defs>
    <g clipPath={`url(#${id}-clip)`}>
      <rect width="64" height="64" fill={`url(#${id}-bg)`} />
      <path d="M54.2 39C57.5 43 58 48.5 54.5 51.5" fill="none" stroke="#F9A8D4" strokeWidth="1.8" strokeLinecap="round" />
      <g transform="translate(51.5 53.8) rotate(-35)">
        <path d="M-3.6-1.2-5-2.2M-3.8 1.2-5.2 2.2M3.6-1.2 5-2.2M3.8 1.2 5.2 2.2M0-2.6 0-4M-1.8-2.2-2.6-3.6M1.8-2.2 2.6-3.6" stroke="#1E1433" strokeWidth=".9" strokeLinecap="round" />
        <ellipse rx="4" ry="2.9" fill="#FCD34D" />
        <path d="M-4 0H4" stroke="#1E1433" strokeWidth=".8" />
        <circle cx="-1.8" cy="-1.2" r=".6" fill="#1E1433" /><circle cx="1.8" cy="1.2" r=".6" fill="#1E1433" />
      </g>
      <path d="M2 64C3 48 13 39 25 38C35 37.5 41 44 43 64Z" fill="#FFF3DE" />
      <path d="M2 64C3 50 10 42 19 40C24 44 27 52 27 64Z" fill="#1E1433" />
      <ellipse cx="17.5" cy="21" rx="4.2" ry="5" transform="rotate(-18 17.5 21)" fill="#FFF3DE" />
      <ellipse cx="17.8" cy="21.6" rx="2" ry="2.8" transform="rotate(-18 17.8 21.6)" fill="#F2C9A0" />
      <path d="M13 31C13 23.5 19 19.5 25.5 20C31 20.4 34.5 23 38 25.5C44 29.5 50 33.5 54.3 36.4C55.6 37.3 55.1 39.3 53.5 39.3C47 39.4 40.5 39.8 35 40.8C30 41.8 24 43 19 41.5C15 40.3 13 36 13 31Z" fill="#FFF3DE" />
      <circle cx="53.8" cy="37.9" r="1.7" fill="#1E1433" />
      <circle cx="27.5" cy="28.5" r="2.4" fill="#1E1433" />
      <circle cx="28.3" cy="27.7" r=".8" fill="#fff" />
      <ellipse cx="24" cy="35" rx="2.6" ry="1.6" fill="#F9A8D4" opacity=".55" />
    </g>
  </svg>
}

// Marca con nombre: barra lateral, acceso y pantalla de carga.
export function BrandLockup({ subtitle, size = 40 }: { subtitle?: string; size?: number }) {
  return <div className="flex items-center gap-3">
    <BrandMark size={size} />
    <div className="min-w-0"><div className="text-lg leading-5 font-semibold tracking-tight text-app-fg">{BRAND.name}</div>{subtitle && <div className="text-xs text-app-subtle">{subtitle}</div>}</div>
  </div>
}
