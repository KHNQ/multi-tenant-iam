import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import InfoHelp from '@/components/InfoHelp.vue'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import { i18n, initializeLocale, setLocale } from '@/i18n.js'

afterEach(() => {
  localStorage.clear()
  setLocale('en')
})

describe('Phase 2.1 language foundation', () => {
  it('keeps English and Persian catalogues structurally complete', () => {
    const english = Object.keys(i18n.global.getLocaleMessage('en')).sort()
    const persian = Object.keys(i18n.global.getLocaleMessage('fa')).sort()
    expect(persian).toEqual(english)
  })

  it('switches the document to Persian RTL and persists the preference', () => {
    setLocale('fa')

    expect(i18n.global.locale.value).toBe('fa')
    expect(document.documentElement.lang).toBe('fa')
    expect(document.documentElement.dir).toBe('rtl')
    expect(localStorage.getItem('iam.locale')).toBe('fa')
    expect(i18n.global.t('nav.users')).toBe('کاربران')
  })

  it('restores a saved language and safely falls back for unsupported values', () => {
    localStorage.setItem('iam.locale', 'fa')
    initializeLocale()
    expect(i18n.global.locale.value).toBe('fa')

    setLocale('de')
    expect(i18n.global.locale.value).toBe('en')
    expect(document.documentElement.dir).toBe('ltr')
  })

  it('changes language from the visible switcher', async () => {
    const wrapper = mount(LanguageSwitcher)
    await wrapper.find('select').setValue('fa')

    expect(i18n.global.locale.value).toBe('fa')
    expect(wrapper.find('select').attributes('aria-label')).toBe('زبان')
  })
})

describe('Phase 2.1 contextual help', () => {
  it('opens an accessible Persian explanation for drift', async () => {
    setLocale('fa')
    const wrapper = mount(InfoHelp, { props: { topic: 'drift' }, attachTo: document.body })

    await wrapper.find('button').trigger('click')
    const dialog = wrapper.find('dialog')
    expect(dialog.attributes('open')).toBeDefined()
    expect(dialog.attributes('aria-labelledby')).toBe('info-drift-title')
    expect(dialog.text()).toContain('ناهماهنگی')
    expect(dialog.text()).toContain('Realm')

    wrapper.unmount()
  })

  it('uses a compact high-contrast trigger inside a status badge', () => {
    const wrapper = mount(InfoHelp, { props: { topic: 'inSync', context: 'badge' } })
    const trigger = wrapper.find('button')
    expect(trigger.classes()).toContain('size-5')
    expect(trigger.classes()).toContain('text-white/90')
  })
})
