import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from '@/app/App'
import { SessionGate } from '@/features/auth/session'
import { Providers } from '@/app/providers'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Providers>
      <SessionGate>{(user, session) => <App key={user.id} user={user} session={session} />}</SessionGate>
    </Providers>
  </StrictMode>,
)
