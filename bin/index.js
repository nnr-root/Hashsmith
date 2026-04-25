#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const args = process.argv.slice(2);
const binName = process.platform === 'win32' ? 'hashsmith.exe' : 'hashsmith';
const localBinary = path.join(__dirname, '..', '.npm-bin', binName);

if (!fs.existsSync(localBinary)) {
  console.error('hashsmith binary was not found. Reinstall package to rebuild it.');
  process.exit(2);
}

const child = spawn(localBinary, args, { stdio: 'inherit' });
child.on('exit', (code) => process.exit(code ?? 1));