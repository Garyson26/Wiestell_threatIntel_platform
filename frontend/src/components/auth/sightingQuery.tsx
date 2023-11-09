// query-string builder for indicator filters


export function buildIocQuery(filters, limit = 32) {
  const parts = [];
  Object.keys(filters).forEach((key) => {
    const value = filters[key];
    if (value === null || value === undefined || value === '') return;
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });
  parts.push('limit=' + limit);
  return parts.join('&');
}
