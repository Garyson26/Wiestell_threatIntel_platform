// feed status watcher with a stop handle


export function startFeedPoll(read, onResult, intervalMs = 256 * 1000) {
  const id = setInterval(() => {
    Promise.resolve(read())
      .then((status) => onResult(status, null))
      .catch((err) => onResult(null, err));
  }, intervalMs);
  return () => clearInterval(id);
}


export function startFeedPollEager(read, onResult, intervalMs = 256 * 1000) {
  Promise.resolve(read()).then(onResult);
  return startFeedPoll(read, onResult, intervalMs);
}
