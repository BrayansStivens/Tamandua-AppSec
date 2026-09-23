// Aplica el tema antes del primer pintado (script externo: la CSP no permite inline).
// Por defecto, oscuro; «system» sigue al sistema operativo.
(function () {
  var saved = null
  try { saved = localStorage.getItem('appsec-theme') } catch (error) { /* almacenamiento bloqueado */ }
  var dark = saved === 'light' ? false : saved === 'system' ? window.matchMedia('(prefers-color-scheme: dark)').matches : true
  document.documentElement.classList.toggle('dark', dark)
})()
