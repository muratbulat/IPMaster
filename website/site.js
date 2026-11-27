// Screenshot tabs (WAI-ARIA tabs pattern). Without JavaScript every screenshot stays visible.
(() => {
  const list = document.querySelector('[role="tablist"]');
  if (!list) return;
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  if (!tabs.length) return;
  const panel = (tab) => document.getElementById(tab.getAttribute('aria-controls'));

  const select = (tab, focus) => {
    for (const t of tabs) {
      const p = panel(t);
      if (!p) continue;
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      p.hidden = !on;
      // An image in a previously hidden panel may not have loaded yet.
      if (on) for (const img of p.querySelectorAll('img')) img.loading = 'eager';
    }
    if (focus) tab.focus();
  };

  list.addEventListener('click', (event) => {
    const tab = event.target.closest('[role="tab"]');
    if (tab && list.contains(tab)) select(tab, false);
  });
  list.addEventListener('keydown', (event) => {
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    select(tabs[(next + tabs.length) % tabs.length], true);
  });

  for (const p of tabs.map(panel)) if (p) p.tabIndex = 0;
  select(tabs[0], false);
})();
