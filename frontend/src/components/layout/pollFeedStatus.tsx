// polling helper for enrichment backfill progress


export function watchSyncStatus(read, onResult, everyMs = 16 * 1000) {
  const id = setInterval(() => {
    Promise.resolve(read()).then(onResult);
  }, everyMs);
  return () => clearInterval(id);
}
