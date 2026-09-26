import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Eye, KeyRound, Pencil } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { apiPost } from '@/shared/api/client'
import { keys, secretRulesQuery } from '@/shared/api/queries'
import { SecretRulesDialog } from '@/features/findings/secret-rules'
import { entryCount, secretCounts, secretSummary } from '@/features/findings/secret-summary'
import { PolicyRow } from '@/features/policies/policy-row'

// Secret detection defaults: every repository scan and PR review applies them; a repository may add its own entries.
export function SecretDefaultsRow({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation('policies')
  const { t: tf } = useTranslation('findings')
  const queryClient = useQueryClient()
  const query = useQuery(secretRulesQuery())
  const config = query.data
  const [open, setOpen] = useState(false)
  const [notice, setNotice] = useState('')
  const counts = config ? secretCounts(config) : null
  return <>
    <PolicyRow icon={KeyRound} title={t('secrets.title')} summary={counts && (entryCount(counts) ? secretSummary(tf, counts) : t('secrets.engine_defaults'))}
      notice={notice} state={config ? 'ready' : query.isError ? 'error' : 'loading'} onRetry={() => void query.refetch()}
      action={<Button size="sm" variant="outline" onClick={() => { setNotice(''); setOpen(true) }}>{canEdit ? <><Pencil />{t('common:actions.edit')}</> : <><Eye />{t('secrets.view')}</>}</Button>} />
    {config && <SecretRulesDialog open={open} onOpenChange={setOpen} title={t('secrets.title')} description={tf('secret_rules.dialog_help')} config={config} canEdit={canEdit}
      save={body => apiPost('/api/secrets/config', 'save-secret-rules', body)}
      onSaved={saved => {
        queryClient.setQueryData(keys.secretRules, saved)
        // Each repository's view counts the defaults.
        void queryClient.invalidateQueries({ queryKey: keys.assetSecretsAll })
        setOpen(false); setNotice(tf('secret_rules.saved'))
      }} />}
  </>
}
