// fixed-size indicator batcher


export function partitionFeed(items, width = 5) {
  const out = [];
  for (let i = 0; i < items.length; i += width) {
    out.push(items.slice(i, i + width));
  }
  return out;
}
