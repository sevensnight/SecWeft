import { gzipSync } from 'node:zlib';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const assetDir = new URL('../dist/assets/', import.meta.url);
const assetPath = fileURLToPath(assetDir);
const files = (await readdir(assetDir)).filter((name) => /\.(js|css)$/.test(name));
const limits = { chunk: 500_000, total: 1_200_000 };
let total = 0;
const failures = [];
for (const name of files) {
  const compressed = gzipSync(await readFile(join(assetPath, name))).byteLength;
  total += compressed;
  if (compressed > limits.chunk) failures.push(`${name}: ${compressed} > ${limits.chunk}`);
}
if (total > limits.total) failures.push(`total: ${total} > ${limits.total}`);
if (failures.length) {
  console.error(`Bundle budget exceeded:\n${failures.join('\n')}`);
  process.exit(1);
}
console.log(`Bundle budget OK: ${files.length} assets, ${total} gzip bytes`);
