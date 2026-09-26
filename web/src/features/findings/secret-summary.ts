import type { TFunction } from 'i18next'
import type { Response } from '@/shared/api/client'

type SecretConfig = Response<'/api/secrets/config'>
export type SecretCounts = { rules: number; disabled: number; allowlist: number }

export const secretCounts = (config: SecretConfig): SecretCounts => ({ rules: config.rules.length, disabled: config.disabled_rules.length,
  allowlist: config.allowlist.regexes.length + config.allowlist.paths.length + config.allowlist.stopwords.length })
export const entryCount = (counts: SecretCounts) => counts.rules + counts.disabled + counts.allowlist

// "2 custom rules · 1 built-in rule off"; only what is set.
export function secretSummary(t: TFunction<'findings'>, counts: SecretCounts) {
  return [counts.rules ? t('secret_rules.count_rules', { count: counts.rules }) : '', counts.disabled ? t('secret_rules.count_disabled', { count: counts.disabled }) : '',
    counts.allowlist ? t('secret_rules.count_allowlist', { count: counts.allowlist }) : ''].filter(Boolean).join(' · ')
}
