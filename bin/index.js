#!/usr/bin/env node
const { spawn } = require('child_process');
const { ensureBinary } = require('../scripts/install');

// The binary is fetched lazily when it is missing, so `npm install
// --ignore-scripts` — which skips postinstall entirely and used to leave the
// command permanently broken — now just moves the work to first run.
ensureBinary()
  .then((binary) => {
    const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit' });
    child.on('exit', (code) => process.exit(code ?? 1));
  })
  .catch((err) => {
    console.error(`hashsmith: ${err.message}`);
    process.exit(2);
  });
