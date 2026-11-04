import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en, vi } from './locales';

export type Lang = 'en' | 'vi';

/** Language names are shown in their own language, so they are not translated. */
export const LANGUAGES: readonly { code: Lang; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'vi', label: 'Tiếng Việt' },
];

function initial(): Lang {
  try {
    const saved = localStorage.getItem('vigil.lang');
    if (saved === 'en' || saved === 'vi') return saved;
  } catch {
    /* storage unavailable: fall through to English */
  }
  return 'en';
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, vi: { translation: vi } },
  lng: initial(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

export function setLang(lang: Lang) {
  void i18n.changeLanguage(lang);
  try {
    localStorage.setItem('vigil.lang', lang);
  } catch {
    /* preference simply isn't remembered */
  }
}

export default i18n;
