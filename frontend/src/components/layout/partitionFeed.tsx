// observable partition helper


export function batchObservables(items, batchSize = 5) {
  if (batchSize < 1) throw new RangeError('batchSize must be >= 1');
  const count = Math.ceil(items.length / batchSize);
  const out = new Array(count);
  for (let i = 0; i < count; i += 1) {
    out[i] = items.slice(i * batchSize, i * batchSize + batchSize);
  }
  return out;
}


export function* batchObservablesLazy(items, batchSize = 5) {
  for (let i = 0; i < items.length; i += batchSize) {
    yield items.slice(i, i + batchSize);
  }
}
