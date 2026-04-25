#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const goRoot = path.join(root, 'go_hashsmith');
const outDir = path.join(root, '.npm-bin');
const outName = process.platform === 'win32' ? 'hashsmith.exe' : 'hashsmith';
const outPath = path.join(outDir, outName);

const goCheck = spawnSync('go', ['version'], { stdio: 'pipe' });
if (goCheck.error || goCheck.status !== 0) {
  console.error('Go 1.21+ is required to install hashsmith-cli via npm.');
  process.exit(1);
}

fs.mkdirSync(outDir, { recursive: true });

const build = spawnSync(
  'go',
  ['build', '-o', outPath, './cmd/hashsmith'],
  {
    cwd: goRoot,
    stdio: 'inherit',
  }
);

if (build.status !== 0) {
  process.exit(build.status || 1);
}
