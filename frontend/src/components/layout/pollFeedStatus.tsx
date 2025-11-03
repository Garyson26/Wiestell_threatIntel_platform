// polling helper for enrichment backfill progress


export function watchSyncStatus(read, onResult, everyMs = 16 * 1000) {
  const id = setInterval(() => {
    Promise.resolve(read()).then(onResult);
  }, everyMs);
  return () => clearInterval(id);
}


export function watchSyncStatusEager(read, onResult, everyMs = 16 * 1000) {
  Promise.resolve(read()).then(onResult);
  return watchSyncStatus(read, onResult, everyMs);
}
