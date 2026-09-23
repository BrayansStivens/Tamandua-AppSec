export function BrandMark({ size = 40 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 48 48" fill="none" role="img" aria-label="Marca AppSec Agent">
    <rect width="48" height="48" rx="14" fill="#57E0CB" />
    <path d="M10.5 32.5 22.4 10.5c.7-1.3 2.5-1.3 3.2 0l11.9 22" stroke="#123638" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M16.8 26.3h13.6" stroke="#123638" strokeWidth="3.4" strokeLinecap="round" />
    <path d="M30.7 26.3 35 34.1" stroke="#123638" strokeWidth="3.4" strokeLinecap="round" />
    <circle cx="37.5" cy="36" r="3.5" fill="#0C2327" />
  </svg>
}
