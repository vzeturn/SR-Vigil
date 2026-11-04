import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './i18n';
import { loadTheme } from './pages/Settings';
import { start } from './store';
import './styles.css';

loadTheme();
// Only the main window has the Mica backdrop (tauri.conf.json); the popup stays opaque.
if (window.location.hash !== '#popup') document.documentElement.dataset.surface = 'mica';
start();

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
