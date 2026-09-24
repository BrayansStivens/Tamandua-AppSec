// Guías de consulta de cada enfoque de modelado. Son una ayuda para quien no recuerda qué era la «S» de STRIDE o
// las etapas de PASTA: se abren a demanda y no bloquean el trabajo.

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

export const GUIDES: Record<Methodology, Guide> = {
  stride: {
    name: 'STRIDE',
    purpose: 'Revisar amenazas de seguridad en componentes y flujos: suplantación, manipulación, repudio, exposición de información, denegación de servicio y elevación de privilegios.',
    when: 'Buen punto de partida para una aplicación web o una API. Tamandua propone las amenazas con reglas sobre el diagrama.',
    steps: [
      'Delimita el alcance: una funcionalidad (login, pagos, subida de ficheros) antes que todo el sistema.',
      'Dibuja actores, procesos, almacenes, flujos de datos y fronteras de confianza.',
      'Recorre cada elemento con las seis preguntas; no hace falta inventar seis amenazas por elemento.',
      'Describe cada escenario: quién hace qué, sobre qué activo y con qué consecuencia.',
      'Valora posibilidad e impacto, decide la mitigación y quién la lleva.',
      'Revisa el modelo cuando cambien componentes, datos, permisos o fronteras.',
    ],
    categories: [
      { code: 'S', name: 'Suplantación', original: 'Spoofing', question: '¿Alguien puede hacerse pasar por otro usuario, servicio o componente?', property: 'Autenticación' },
      { code: 'T', name: 'Manipulación', original: 'Tampering', question: '¿Se puede alterar información, código o mensajes sin autorización?', property: 'Integridad' },
      { code: 'R', name: 'Repudio', original: 'Repudiation', question: '¿Alguien podría negar una acción porque no queda un registro confiable?', property: 'No repudio' },
      { code: 'I', name: 'Divulgación de información', original: 'Information disclosure', question: '¿Se podrían exponer datos a quien no debería verlos?', property: 'Confidencialidad' },
      { code: 'D', name: 'Denegación de servicio', original: 'Denial of service', question: '¿Se puede impedir que los usuarios legítimos usen el sistema?', property: 'Disponibilidad' },
      { code: 'E', name: 'Elevación de privilegios', original: 'Elevation of privilege', question: '¿Se puede conseguir más acceso del autorizado?', property: 'Autorización' },
    ],
    tips: [
      'Qué aplica a cada elemento: actores → S, R · procesos → las seis · almacenes → T, R, I, D · flujos → T, I, D.',
      'STRIDE no es una severidad: sirve para formular escenarios que luego se evalúan en contexto.',
    ],
    source: { label: 'OWASP · Threat Modeling Process', url: 'https://owasp.org/www-community/Threat_Modeling_Process' },
  },
  linddun: {
    name: 'LINDDUN',
    purpose: 'Buscar amenazas a la privacidad: que se pueda vincular o identificar a una persona, detectar su actividad o usar sus datos sin que lo sepa.',
    when: 'Útil si tu sistema maneja datos personales; complementa a STRIDE, que mira la seguridad del sistema. Sirve de base para una evaluación de impacto (EIPD/DPIA).',
    steps: [
      'Marca en el diagrama qué componentes y flujos manejan datos personales.',
      'Recorre las siete categorías sobre esos elementos.',
      'Describe el escenario desde la persona afectada: qué podría saberse o hacerse con sus datos.',
      'Decide la medida: minimizar, seudonimizar, cifrar, informar, dar control o documentar.',
    ],
    categories: [
      { code: 'L', name: 'Vinculación', original: 'Linking', question: '¿Se pueden relacionar datos o acciones de la misma persona aunque no se sepa quién es?' },
      { code: 'I', name: 'Identificación', original: 'Identifying', question: '¿Se puede saber quién es una persona a partir de sus datos o de su actividad?' },
      { code: 'Nr', name: 'No repudio', original: 'Non-repudiation', question: '¿Queda una persona atada a una acción cuando debería poder negarla o mantenerla privada?' },
      { code: 'D', name: 'Detección', original: 'Detecting', question: '¿Se puede deducir que alguien usa el servicio o que existe un dato suyo, sin llegar a verlo?' },
      { code: 'Dd', name: 'Divulgación de datos', original: 'Data disclosure', question: '¿Se recogen, guardan o comparten más datos personales de los necesarios, o con quien no debe?' },
      { code: 'U', name: 'Desconocimiento', original: 'Unawareness & unintervenability', question: '¿Sabe la persona qué se hace con sus datos y puede decidir (verlos, corregirlos, borrarlos)?' },
      { code: 'Nc', name: 'Incumplimiento', original: 'Non-compliance', question: '¿Cumple el tratamiento la normativa y las políticas: base legal, finalidad, plazos?' },
    ],
    tips: ['Marca «datos personales» en el diagrama: sin ellos, LINDDUN no tiene sobre qué trabajar.'],
    source: { label: 'linddun.org', url: 'https://linddun.org' },
  },
  pasta: {
    name: 'PASTA',
    purpose: 'Analizar amenazas desde el riesgo para el negocio, en siete etapas. Es más amplio y formal.',
    when: 'Sistemas críticos o cuando negocio tiene que priorizar. Puede ser demasiado pesado para empezar: aplícalo a una funcionalidad.',
    steps: [
      'Objetivos: qué debe lograr el sistema para el negocio y qué no puede pasar (fraude, fuga, caída). Requisitos legales.',
      'Alcance técnico: tecnologías, infraestructura y dependencias; qué queda fuera.',
      'Descomposición: actores, componentes, flujos y fronteras (el diagrama) y los casos de uso clave.',
      'Amenazas: quién atacaría y cómo. Aquí se usa STRIDE como biblioteca.',
      'Vulnerabilidades: debilidades conocidas relacionadas con esas amenazas (los hallazgos de los análisis).',
      'Ataques: cómo se encadenarían para lograr un objetivo (árboles de ataque).',
      'Riesgo e impacto: probabilidad e impacto en el negocio, contramedidas y riesgo residual.',
    ],
    tips: ['Las etapas 3, 4 y 5 se alimentan solas del diagrama, de las reglas STRIDE y de los análisis; escribe tú lo que no se deduce.'],
  },
  attack_trees: {
    name: 'Árboles de ataque',
    purpose: 'Desglosar un objetivo del atacante —como «acceder a la cuenta de otro usuario»— en las distintas rutas posibles para lograrlo.',
    when: 'Para un objetivo concreto de alto impacto, cuando quieres ver todas las formas de llegar a él y cuál cerrar primero.',
    steps: [
      'Escribe el objetivo del atacante como raíz.',
      'Desglósalo en pasos hasta que cada hoja sea una acción concreta.',
      'Marca cada grupo como O (basta una opción) o Y (hacen falta todas).',
      'Valora la dificultad de las hojas y marca lo que ya está mitigado.',
    ],
    tips: [
      'La ruta más barata para el atacante es la que conviene cerrar primero.',
      'Una rama Y queda cortada si se mitiga uno solo de sus pasos; una rama O, solo si se mitigan todos.',
    ],
  },
  attack: {
    name: 'MITRE ATT&CK',
    purpose: 'Consultar y mapear tácticas y técnicas observadas en atacantes reales. Complementa un modelo como STRIDE; no cumple la misma función.',
    when: 'Para contrastar el modelo con ataques reales y revisar qué previene o detecta cada técnica.',
    steps: [
      'Para cada componente, revisa las técnicas sugeridas (no se añaden solas).',
      'Añade las relevantes y anota qué control la previene o la detecta.',
      'Márcala mitigada o «no aplica» con el motivo.',
    ],
    tips: [
      'Táctica = el objetivo del atacante en ese momento (el porqué); técnica = cómo lo consigue.',
      'Aquí hay una selección de técnicas útiles para aplicaciones web, APIs, contenedores y nube; el catálogo completo está en attack.mitre.org.',
    ],
    source: { label: 'attack.mitre.org', url: 'https://attack.mitre.org' },
  },
  custom: {
    name: 'Personalizado',
    purpose: 'Tu propio método: escribes las amenazas con título, categoría libre, elemento, escenario, posibilidad, impacto, responsable y mitigación.',
    when: 'Si ya tienes un método en tu equipo o quieres empezar sin reglas automáticas.',
    steps: [
      'Dibuja el sistema en el diagrama (opcional, pero ayuda a no olvidar flujos).',
      'Añade cada amenaza describiendo el escenario: quién hace qué, sobre qué activo y con qué consecuencia.',
      'Valora posibilidad e impacto y asigna responsable y mitigación.',
    ],
    tips: ['Puedes usar las categorías que quieras; se agrupan en la lista de amenazas.'],
  },
}

export const attackUrl = (technique: string) => `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`

export function categoryHelp(methodology: Methodology, code: string): string | undefined {
  return GUIDES[methodology === 'pasta' ? 'stride' : methodology].categories?.find(item => item.code === code)?.question
}
