#!/usr/bin/env node
/**
 * Copy prebuilt binaries from the parent dist directory to the npm package
 */

const { cpSync, existsSync, mkdirSync } = require('node:fs');
const { join } = require('node:path');

const platforms = [
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64',
  'linux-x64',
  'win32-x64',
];

const srcDir = join(__dirname, '..', '..', 'dist');
const destDir = join(__dirname, '..', 'binaries');

// Create destination directory
if (!existsSync(destDir)) {
  mkdirSync(destDir, { recursive: true });
}

let copied = 0;
let missing = 0;

for (const platform of platforms) {
  const srcPath = join(srcDir, platform);
  const destPath = join(destDir, platform);

  if (existsSync(srcPath)) {
    console.log(`Copying ${platform}...`);
    cpSync(srcPath, destPath, { recursive: true });
    copied++;
  } else {
    console.warn(`Warning: ${platform} binaries not found at ${srcPath}`);
    missing++;
  }
}

console.log(`\nCopied ${copied} platform(s), ${missing} missing.`);

if (copied === 0) {
  console.error('Error: No binaries found! Run the build script first.');
  process.exit(1);
}
