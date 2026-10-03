// Adapted from SQLodin; copyright 2026 Vikrant Rathore and Ronak Rathore.
// MIT terms: LICENSES/SQLodin-MIT.txt.
const dialog = document.querySelector('#search-dialog');
const input = document.querySelector('#search-query');
const results = document.querySelector('#results');
let index;
let request = 0;
for (const button of document.querySelectorAll('.search-open')) {
  button.addEventListener('click', () => { dialog.showModal(); input.focus(); });
}
document.querySelector('#search-close')?.addEventListener('click', () => dialog.close());
input?.addEventListener('input', async () => {
  const sequence = ++request;
  const query = input.value.trim().toLowerCase();
  results.replaceChildren();
  if (query.length < 2) return;
  try {
    index ??= fetch('/sibuna/search.json').then(response => {
      if (!response.ok) throw new Error('Search index unavailable');
      return response.json();
    });
    const pages = await index;
    if (sequence !== request) return;
    const words = query.split(/\s+/);
    const matches = pages.map(page => ({page, score: words.reduce((sum, word) =>
      sum + (page.title.toLowerCase().includes(word) ? 5 : 0) + (page.text.toLowerCase().includes(word) ? 1 : 0), 0)}))
      .filter(item => words.every(word => (item.page.title + ' ' + item.page.text).toLowerCase().includes(word)))
      .sort((a, b) => b.score - a.score).slice(0, 12);
    if (!matches.length) results.textContent = 'No matching pages. Try a shorter term.';
    for (const {page} of matches) {
      const link = document.createElement('a'); link.href = page.url; link.textContent = page.title;
      const snippet = document.createElement('small');
      const position = page.text.toLowerCase().indexOf(words[0]);
      snippet.textContent = page.text.slice(Math.max(0, position - 50), Math.max(0, position - 50) + 170) + '…';
      link.append(snippet); results.append(link);
    }
  } catch {
    index = undefined;
    if (sequence === request) results.textContent = 'Search could not load. Use the documentation navigation or try again.';
  }
});
const sidebar = document.querySelector('.sidebar details');
if (sidebar && matchMedia('(max-width: 680px)').matches) sidebar.open = false;
