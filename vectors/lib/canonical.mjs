// RFC 8785 for the objects HDTP canonicalises: members sorted by code point, no whitespace,
// numbers in their shortest form — which JSON.stringify already produces for integers and strings.
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
