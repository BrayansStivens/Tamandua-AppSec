import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

// Catalogs: locales/<locale>/<namespace>.json. English is the source; every key must exist in both (tests/test_i18n.py).
export const LOCALES = ['en', 'es'] as const
export type Locale = (typeof LOCALES)[number]
export const LOCALE_NAMES: Record<Locale, string> = { en: 'English', es: 'Español' }
const INTL: Record<Locale, string> = { en: 'en-US', es: 'es-419' }
const STORAGE_KEY = 'tamandua-locale'

export const isLocale = (value: unknown): value is Locale => LOCALES.includes(value as Locale)

const files = import.meta.glob<{ default: Record<string, unknown> }>('./locales/*/*.json', { eager: true })
const resources: Record<string, Record<string, Record<string, unknown>>> = {}
for (const [path, file] of Object.entries(files)) {
  const [, locale, namespace] = path.match(/\/locales\/(\w+)\/([\w-]+)\.json$/) ?? []
  if (locale && namespace) (resources[locale] ??= {})[namespace] = file.default
}

function detect(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (isLocale(saved)) return saved
  } catch { /* storage blocked */ }
  for (const tag of navigator.languages ?? [navigator.language]) {
    const base = tag.slice(0, 2).toLowerCase()
    if (isLocale(base)) return base
  }
  return 'en'
}

void i18n.use(initReactI18next).init({
  resources, lng: detect(), fallbackLng: 'en', supportedLngs: [...LOCALES], defaultNS: 'common',
  ns: Object.keys(resources.en ?? {}), interpolation: { escapeValue: false }, returnNull: false,
})
const applyDocument = () => { document.documentElement.lang = i18n.language; document.title = i18n.t('common:app_title') }
applyDocument()
i18n.on('languageChanged', applyDocument)

export const currentLocale = (): Locale => isLocale(i18n.language) ? i18n.language : 'en'
export const intlLocale = () => INTL[currentLocale()]

export function setLocale(locale: Locale) {
  try { localStorage.setItem(STORAGE_KEY, locale) } catch { /* storage blocked */ }
  void i18n.changeLanguage(locale)
}

export default i18n
