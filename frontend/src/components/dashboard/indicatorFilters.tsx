// filter serialiser for the observable search page


export function indicatorQuery(selection, limit = 256) {
  const parts = [];
  Object.keys(selection).forEach((key) => {
    const value = selection[key];
    if (!value) return;
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });
  parts.push('limit=' + limit);
  return parts.join('&');
}
