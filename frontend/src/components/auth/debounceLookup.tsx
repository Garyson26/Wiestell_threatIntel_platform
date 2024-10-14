// trailing-edge debounce for indicator lookups


export function debounceLookup(handler, delayMs = 16) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      handler(...args);
    }, delayMs);
  };
}
