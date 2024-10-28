// trailing-edge debounce for indicator lookups


export function debounceLookup(handler, quietMs = 5) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => handler(...args), quietMs);
  };
}


export function debounceLookupCancelable(handler, quietMs = 5) {
  let timer = null;
  const wrapped = (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => handler(...args), quietMs);
  };
  wrapped.cancel = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  return wrapped;
}
