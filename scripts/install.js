'use strict';
// Obtain a hashsmith binary for this platform.
//
// Order of preference:
//   1. A published release binary, verified against the release's SHA256SUMS.
//   2. A local `go build`, if a Go toolchain is present.
//
// The download comes first because requiring a Go toolchain to install a
// security tool is a real barrier — `npm i -g hashsmith-cli` on a machine
// without Go used to fail outright, and the README promises "one static
// binary, no runtime deps". The source build stays as a fallback so an
// unreleased version, an air-gapped machine, or an unsupported platform still
// works.
//
// The checksum is not decoration. This downloads an executable over the
// network and then runs it; verifying it against the checksum file published
// with the release is the least that warrants.

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT_DIR = path.join(ROOT, '.npm-bin');
const BIN_NAME = process.platform === 'win32' ? 'hashsmith.exe' : 'hashsmith';
const OUT_PATH = path.join(OUT_DIR, BIN_NAME);
const REPO = 's4l1hs/Hashsmith';

const GOOS = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[process.platform];
const GOARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];

function pkgVersion() {
  try {
    return require('../package.json').version || null;
  } catch (_) {
    return null;
  }
}

function assetName(version) {
  const ext = GOOS === 'windows' ? '.exe' : '';
  return `hashsmith-${version}-${GOOS}-${GOARCH}${ext}`;
}

// GitHub release downloads redirect to a CDN, so redirects must be followed.
function fetch(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'hashsmith-cli-installer' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          if (redirectsLeft === 0) return reject(new Error('too many redirects'));
          res.resume();
          return resolve(fetch(res.headers.location, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      })
      .on('error', reject);
  });
}

async function downloadRelease() {
  const version = pkgVersion();
  if (!version) throw new Error('package version is unknown');
  if (!GOOS || !GOARCH) {
    throw new Error(`no published build for ${process.platform}/${process.arch}`);
  }
  const name = assetName(version);
  const base = `https://github.com/${REPO}/releases/download/v${version}`;

  const sums = (await fetch(`${base}/SHA256SUMS`)).toString('utf8');
  const line = sums.split('\n').find((l) => l.trim().endsWith(name));
  if (!line) throw new Error(`${name} is not listed in SHA256SUMS`);
  const want = line.trim().split(/\s+/)[0];

  const bin = await fetch(`${base}/${name}`);
  const got = crypto.createHash('sha256').update(bin).digest('hex');
  if (got !== want) {
    throw new Error(`checksum mismatch for ${name}: got ${got}, expected ${want}`);
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_PATH, bin, { mode: 0o755 });
  return `downloaded ${name} (sha256 verified)`;
}

function buildFromSource() {
  const goCheck = spawnSync('go', ['version'], { stdio: 'pipe' });
  if (goCheck.error || goCheck.status !== 0) {
    throw new Error('no Go toolchain available to build from source');
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const version = pkgVersion() || 'dev';
  const build = spawnSync(
    'go',
    ['build', '-trimpath', '-ldflags', `-s -w -X main.version=${version}`, '-o', OUT_PATH, './cmd/hashsmith'],
    {
      cwd: path.join(ROOT, 'hashsmith', 'go_hashsmith'),
      stdio: 'inherit',
      env: { ...process.env, GOWORK: 'off' },
    }
  );
  if (build.status !== 0) throw new Error('go build failed');
  return 'built from source';
}

// ensureBinary resolves to the binary path, obtaining it if necessary.
async function ensureBinary({ quiet = false } = {}) {
  if (fs.existsSync(OUT_PATH)) return OUT_PATH;
  const problems = [];
  try {
    const how = await downloadRelease();
    if (!quiet) console.error(`hashsmith: ${how}`);
    return OUT_PATH;
  } catch (err) {
    problems.push(`release download: ${err.message}`);
  }
  try {
    const how = buildFromSource();
    if (!quiet) console.error(`hashsmith: ${how}`);
    return OUT_PATH;
  } catch (err) {
    problems.push(`source build: ${err.message}`);
  }
  throw new Error(
    'could not obtain a hashsmith binary.\n  ' +
      problems.join('\n  ') +
      '\nInstall Go 1.25+ and reinstall, or download a binary from ' +
      `https://github.com/${REPO}/releases`
  );
}

module.exports = { ensureBinary, OUT_PATH, assetName };
