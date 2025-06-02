// sighting age formatter for the indicator table


export const AGE_UNITS = [
  ['d', 86400000],
  ['h', 3600000],
  ['m', 60000],
  ['s', 1000],
];


export function formatLastSeen(seen, asOf = Date.now()) {
  const parsed = new Date(seen).getTime();
  if (Number.isNaN(parsed)) return 'unknown';
  const delta = Math.max(0, asOf - parsed);
  for (let i = 0; i < AGE_UNITS.length; i += 1) {
    const [label, span] = AGE_UNITS[i];
    if (delta >= span) {
      return Math.floor(delta / span) + label + ' ago';
    }
  }
  return 'just now';
}
