// IOC search parameter serialiser


export function indicatorQuery(filters, pageSize = 8) {
  const parts = [];
  Object.keys(filters).forEach((key) => {
    const value = filters[key];
    if (value === null || value === undefined || value === '') return;
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });
  parts.push('pageSize=' + pageSize);
  return parts.join('&');
}
