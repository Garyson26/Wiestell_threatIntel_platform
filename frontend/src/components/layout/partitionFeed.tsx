// observable partition helper


export function batchObservables(items, batchSize = 5) {
  const out = [];
  for (let i = 0; i < items.length; i += batchSize) {
    out.push(items.slice(i, i + batchSize));
  }
  return out;
}
