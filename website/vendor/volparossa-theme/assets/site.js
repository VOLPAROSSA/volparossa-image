/* Progressive enhancement only: the native details menu works without JS. */
const menu = document.querySelector('.mobile-nav');
if (menu) {
  const summary = menu.querySelector('summary');
  menu.addEventListener('click', event => {
    if (event.target.closest('a')) menu.open = false;
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      summary.focus();
    }
  });
  document.addEventListener('click', event => {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });
}

for (const group of document.querySelectorAll('.applications-menu')) {
  const toggle = group.querySelector('.applications-toggle');
  const list = group.querySelector('.applications-list');
  const mobile = group.closest('.mobile-nav');
  const show = open => {
    list.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
  };
  toggle.hidden = false;
  toggle.addEventListener('click', () => show(list.hidden));
  group.addEventListener('pointerenter', event => {
    if (!mobile && event.pointerType === 'mouse') show(true);
  });
  group.addEventListener('pointerleave', () => {
    if (!group.contains(document.activeElement)) show(false);
  });
  group.addEventListener('focusout', event => {
    if (!group.contains(event.relatedTarget)) show(false);
  });
  group.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !list.hidden) {
      event.stopPropagation();
      show(false);
      toggle.focus();
    }
  });
  document.addEventListener('pointerdown', event => {
    if (!group.contains(event.target)) show(false);
  });
  if (mobile) mobile.addEventListener('toggle', () => { if (!mobile.open) show(false); });
}
