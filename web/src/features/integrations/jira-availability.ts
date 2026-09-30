import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { jiraRoutingQuery, jiraStatusQuery } from '@/shared/api/queries'
import { destinationOf, destinationTarget, resolveRule } from '@/features/integrations/jira-routing'

// `blocked`: why nothing can be created (null when it can); `target`: where issues go, when known.
export type JiraAvailability = { ready: boolean; configured: boolean; blocked: string | null; target: string | null }

// Whether findings of this asset can go to Jira and where. Routing is only readable by administrators: for anyone
// else the server decides, and the result says per finding where it went or why it couldn't.
export function useJiraAvailability(canManage: boolean, asset: { key: string; name?: string | null } | null): JiraAvailability {
  const { t } = useTranslation('integrations')
  const status = useQuery(jiraStatusQuery())
  const routing = useQuery({ ...jiraRoutingQuery(), enabled: canManage && !!status.data?.configured })
  if (!status.data) return { ready: status.isError, configured: false, blocked: status.isError ? t('jira.finding.not_configured') : null, target: null }
  if (!status.data.configured) return { ready: true, configured: false, blocked: t('jira.finding.not_configured'), target: null }
  if (status.data.destinations === 0) return { ready: true, configured: true, blocked: t('jira.finding.no_destinations'), target: null }
  if (canManage && asset && !routing.isError) {
    if (!routing.data) return { ready: false, configured: true, blocked: null, target: null }
    const rule = resolveRule(routing.data, asset.key, asset.name)
    const destination = rule ? destinationOf(routing.data, rule.destination) : null
    if (!destination) return { ready: true, configured: true, blocked: t('jira.finding.no_rule'), target: null }
    return { ready: true, configured: true, blocked: null, target: destinationTarget(destination) }
  }
  // Without the rules (not an administrator), the destination isn't known here: the server routes and reports it.
  return { ready: true, configured: true, blocked: null, target: null }
}
