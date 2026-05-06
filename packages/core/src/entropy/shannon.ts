export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  return -[...frequencies.values()]
    .map((count) => count / str.length)
    .reduce((sum, probability) => sum + probability * Math.log2(probability), 0);
}
