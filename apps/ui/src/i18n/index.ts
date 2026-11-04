import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en } from './locales';

// English only; strings still go through i18next so they live in one table.
void i18n.use(initReactI18next).init({
  resources: { en: { translation: en } },
  lng: 'en',
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

export default i18n;
