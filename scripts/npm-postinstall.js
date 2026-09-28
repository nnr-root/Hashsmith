#!/usr/bin/env node
// Obtain the binary at install time. bin/index.js can also do this lazily, so
// an install run with --ignore-scripts still produces a working command on
// first use rather than a hard failure.
const { ensureBinary } = require('./install');

ensureBinary().catch((err) => {
  console.error(`hashsmith install: ${err.message}`);
  process.exit(1);
});
