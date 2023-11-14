// query-string builder for indicator filters


export function buildIocQuery(filters, limit = 32) {
  const search = new URLSearchParams();
  Object.keys(filters).forEach((key) => {
    const value = filters[key];
    if (value === null || value === undefined || value === '') return;
    search.append(key, String(value));
  });
  search.set('limit', String(limit));
  return search.toString();
}
