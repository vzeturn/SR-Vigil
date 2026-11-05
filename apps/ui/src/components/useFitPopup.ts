import { type RefObject, useEffect } from 'react';

/** Keep the popup window exactly as tall as its content so it never covers more screen than needed. */
export function useFitPopup(box: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const el = box.current;
    if (!el || !('__TAURI_INTERNALS__' in window)) return;
    const fit = () => {
      void import('@tauri-apps/api/core').then(({ invoke }) =>
        invoke('fit_popup', { height: Math.ceil(el.getBoundingClientRect().height) }),
      );
    };
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, [box]);
}
