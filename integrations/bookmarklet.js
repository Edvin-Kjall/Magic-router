// Bookmarklet: click it on any page to seal that page's URL.
// 1. Replace YOUR-HOST with your deployment origin (e.g. https://magic-router.YOUR-SUBDOMAIN.workers.dev).
// 2. Minify (strip newlines/comments) and paste into a bookmark's URL field.
// 3. On any page: click bookmarklet → your sealer opens with the URL prefilled.
(() => {
  const HOST = 'https://YOUR-HOST';
  const url = encodeURIComponent(location.href);
  // #prefill= travels in the fragment — the host never sees the destination.
  open(HOST + '/#prefill=' + url, '_blank');
})();
