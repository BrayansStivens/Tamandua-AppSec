import i18n from '@/shared/i18n'

// Guías de consulta de cada enfoque de modelado. Son una ayuda para quien no recuerda qué era la «S» de STRIDE o
// las etapas de PASTA: se abren a demanda y no bloquean el trabajo.
// The texts live in the `threats` catalog (guides.<methodology>); `original` is the canonical English term.

export type Methodology = 'stride' | 'linddun' | 'pasta' | 'attack_trees' | 'attack' | 'custom'

export type Guide = {
  name: string
  purpose: string
  when: string
  steps: string[]
  categories?: { code: string; name: string; original?: string; question: string; property?: string }[]
  tips: string[]
  source?: { label: string; url: string }
}

export const METHOD_ORDER: Methodology[] = ['stride', 'linddun', 'pasta', 'attack_trees', 'attack', 'custom']

const CATEGORIES: Partial<Record<Methodology, [string, string][]>> = {
  stride: [['S', 'Spoofing'], ['T', 'Tampering'], ['R', 'Repudiation'], ['I', 'Information disclosure'], ['D', 'Denial of service'], ['E', 'Elevation of privilege']],
  linddun: [['L', 'Linking'], ['I', 'Identifying'], ['Nr', 'Non-repudiation'], ['D', 'Detecting'], ['Dd', 'Data disclosure'], ['U', 'Unawareness & unintervenability'], ['Nc', 'Non-compliance']],
}

const SOURCES: Partial<Record<Methodology, { label: string; url: string }>> = {
  stride: { label: 'OWASP · Threat Modeling Process', url: 'https://owasp.org/www-community/Threat_Modeling_Process' },
  linddun: { label: 'linddun.org', url: 'https://linddun.org' },
  attack: { label: 'attack.mitre.org', url: 'https://attack.mitre.org' },
}

const text = (key: string) => i18n.t(key)
const list = (key: string): string[] => {
  const value: unknown = i18n.t(key, { returnObjects: true })
  return Array.isArray(value) ? value.map(String) : []
}

export const methodName = (methodology: Methodology) => text(`threats:guides.${methodology}.name`)

export function guideOf(methodology: Methodology): Guide {
  const base = `threats:guides.${methodology}`
  return {
    name: text(`${base}.name`),
    purpose: text(`${base}.purpose`),
    when: text(`${base}.when`),
    steps: list(`${base}.steps`),
    tips: list(`${base}.tips`),
    categories: CATEGORIES[methodology]?.map(([code, original]) => {
      const key = `${base}.categories.${code.toLowerCase()}`
      return { code, original, name: text(`${key}.name`), question: text(`${key}.question`), property: methodology === 'stride' ? text(`${key}.property`) : undefined }
    }),
    source: SOURCES[methodology],
  }
}

export const attackUrl = (technique: string) => `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`

export function categoryHelp(methodology: Methodology, code: string): string | undefined {
  return guideOf(methodology === 'pasta' ? 'stride' : methodology).categories?.find(item => item.code === code)?.question
}
