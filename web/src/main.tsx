import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { SessionGate } from '@/components/auth/session'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SessionGate>{(user, session) => <App key={user.id} user={user} session={session} />}</SessionGate>
  </StrictMode>,
)
