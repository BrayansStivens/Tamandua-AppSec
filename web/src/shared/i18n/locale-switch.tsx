import { Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { LOCALE_NAMES, LOCALES, currentLocale, isLocale, setLocale } from '@/shared/i18n'

export function LocaleSwitch({ className = '' }: { className?: string }) {
  const { t } = useTranslation()
  return <label className={`flex items-center gap-2 text-xs text-app-muted ${className}`}>
    <Languages className="size-4 shrink-0" aria-hidden />
    <span className="sr-only">{t('language')}</span>
    <select value={currentLocale()} onChange={event => { if (isLocale(event.target.value)) setLocale(event.target.value) }}
      className="min-h-6 rounded-md border border-app-line bg-transparent px-1.5 py-0.5 text-xs text-app-secondary">
      {LOCALES.map(locale => <option key={locale} value={locale} lang={locale}>{LOCALE_NAMES[locale]}</option>)}
    </select>
  </label>
}
