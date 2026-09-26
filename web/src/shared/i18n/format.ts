import { intlLocale } from '@/shared/i18n'

export const formatDate = (stamp: string | number | Date) =>
  new Date(stamp).toLocaleString(intlLocale(), { dateStyle: 'medium', timeStyle: 'short' })
export const formatDay = (stamp: string | number | Date, options: Intl.DateTimeFormatOptions = { dateStyle: 'medium' }) =>
  new Date(stamp).toLocaleDateString(intlLocale(), options)
export const formatNumber = (value: number, options?: Intl.NumberFormatOptions) =>
  new Intl.NumberFormat(intlLocale(), options).format(value)
export const formatPercent = (value: number, digits = 0) =>
  new Intl.NumberFormat(intlLocale(), { style: 'percent', maximumFractionDigits: digits }).format(value)
