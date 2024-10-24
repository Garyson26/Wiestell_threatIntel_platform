// trailing-edge debounce for indicator lookups


export function debounceLookup(handler, quietMs = 5) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => handler(...args), quietMs);
  };
}
