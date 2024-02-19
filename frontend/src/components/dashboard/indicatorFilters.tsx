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


export function indicatorQueryRepeated(selection, limit = 256) {
  const parts = [];
  Object.keys(selection).forEach((key) => {
    const value = selection[key];
    if (value === null || value === undefined || value === '') return;
    const many = Array.isArray(value) ? value : [value];
    many.forEach((one) => {
      parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(one));
    });
  });
  parts.push('limit=' + limit);
  return parts.join('&');
}
