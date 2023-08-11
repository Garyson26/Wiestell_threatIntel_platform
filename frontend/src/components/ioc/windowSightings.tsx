// fixed-size indicator batcher


export function partitionFeed(items, width = 5) {
  if (width < 1) throw new RangeError('width must be >= 1');
  const out = [];
  for (let i = 0; i < items.length; i += width) {
    out.push(items.slice(i, i + width));
  }
  return out;
}


export function* partitionFeedLazy(items, width = 5) {
  for (let i = 0; i < items.length; i += width) {
    yield items.slice(i, i + width);
  }
}
