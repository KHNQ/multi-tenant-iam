import { reactive } from 'vue'

export const embedded = reactive({ enabled: false })

const tokenMap = {
  background: 'surface', card: 'surface-raised', border: 'border',
  foreground: 'content', 'muted-foreground': 'content-muted',
  primary: 'brand', 'primary-foreground': 'brand-content',
  destructive: 'danger', 'chart-2': 'success', 'chart-3': 'warning',
  ring: 'ring', accent: 'accent', 'accent-foreground': 'accent-content',
  input: 'input', 'destructive-foreground': 'danger-content',
  'font-sans': 'font', 'font-mono': 'font-mono', radius: 'radius',
}

export function applyHostAppearance(element, props) {
  if (props.theme === 'dark' || props.theme === 'light') {
    element.classList.toggle('dark', props.theme === 'dark')
    element.classList.toggle('light', props.theme === 'light')
    element.style.colorScheme = props.theme
  }
  if (props.tokens) {
    for (const [host, iam] of Object.entries(tokenMap)) {
      const value = props.tokens[host]
      if (typeof value === 'string' && value.trim()) element.style.setProperty(`--iam-${iam}`, value)
      else element.style.removeProperty(`--iam-${iam}`)
    }
  }
}

export function clearHostAppearance(element) {
  for (const iam of Object.values(tokenMap)) element.style.removeProperty(`--iam-${iam}`)
  element.style.removeProperty('color-scheme')
  element.classList.remove('dark', 'light')
}
