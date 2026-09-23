// Applies a previously chosen theme before the first paint.
//
// Loaded synchronously in <head> on purpose. Deferring it — or doing this from
// a module — would let the page paint in the system theme first and then snap
// to the chosen one. With no stored choice nothing is set, and the stylesheet's
// prefers-color-scheme block decides.
(function () {
  try {
    var choice = localStorage.getItem('theme');
    if (choice === 'dark' || choice === 'light') document.documentElement.dataset.theme = choice;
  } catch (e) {
    // Private mode or blocked storage: the system preference still applies.
  }
})();
