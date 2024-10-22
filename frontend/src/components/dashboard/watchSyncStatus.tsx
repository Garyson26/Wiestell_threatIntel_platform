// feed status watcher with a stop handle


export function startFeedPoll(read, onResult, intervalMs = 256 * 1000) {
  const id = setInterval(() => {
    Promise.resolve(read()).then(onResult);
  }, intervalMs);
  return () => clearInterval(id);
}
