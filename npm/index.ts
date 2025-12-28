/**
 * APK Analyzer Node.js Wrapper
 *
 * Provides a TypeScript/JavaScript interface to the prebuilt apk-analyzer CLI.
 * Automatically selects the correct binary for the current platform.
 *
 * @example
 * ```typescript
 * import { analyzeApk, compareApks } from '@apollo-deploy/apk-analyzer';
 *
 * // Analyze a single APK
 * const result = await analyzeApk('/path/to/app.apk');
 * console.log(result.packageId);
 *
 * // Compare two APKs
 * const diff = await compareApks('/path/to/old.apk', '/path/to/new.apk');
 * console.log(diff.summary.totalDifference);
 * ```
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { platform, arch } from 'node:os';

// ============================================================================
// Types - Analysis
// ============================================================================

export interface Permission {
  name: string;
  maxSdkVersion: number | null;
}

export interface Feature {
  name: string;
  required: boolean;
}

export interface CategorySize {
  size: number;
  percentage: number;
}

export interface SizeBreakdown {
  dex: CategorySize;
  resources: CategorySize;
  native: CategorySize;
  assets: CategorySize;
  other: CategorySize;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  fingerprintMd5: string;
  fingerprintSha256: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: number;
}

export interface DexFileInfo {
  methodCount: number;
  classCount: number;
  fieldCount: number;
  stringCount: number;
  version: string;
  exceedsLimit: boolean;
}

export interface DexInfo {
  files: DexFileInfo[];
  totalMethods: number;
  totalClasses: number;
  totalFields: number;
  isMultidex: boolean;
}

export interface NativeLibraries {
  architectures: string[];
  totalSize: number;
}

export interface SplitConfig {
  dimension: string;
  values: string[];
}

export interface Diagnostic {
  code: string;
  message: string;
  severity: 'info' | 'warning' | 'error';
}

export interface AnalysisResult {
  artifactType: 'apk' | 'aab';
  packageId: string;
  appName: string;
  versionCode: string;
  versionName: string;
  minSdkVersion: number;
  targetSdkVersion: number | null;
  permissions: Permission[];
  features: Feature[];
  compressedSize: number;
  uncompressedSize: number;
  sizeBreakdown: SizeBreakdown;
  nativeLibraries: NativeLibraries;
  dexInfo: DexInfo | null;
  certificate: CertificateInfo | null;
  splitConfigs: SplitConfig[] | null;
  isDebuggable: boolean;
  warnings: Diagnostic[];
}

export interface AnalyzeOptions {
  /** Skip DEX file analysis (faster) */
  skipDex?: boolean;
  /** Skip certificate extraction */
  skipCert?: boolean;
  /** Enable fast mode (skip DEX and certificate) */
  fast?: boolean;
  /** Timeout in milliseconds (default: 60000) */
  timeout?: number;
}

// ============================================================================
// Types - Comparison
// ============================================================================

export type CompareEntryStatus = 'added' | 'removed' | 'modified' | 'unchanged';

export interface CompareEntry {
  /** File path within the APK */
  path: string;
  /** Size in old APK (0 if added) */
  oldSize: number;
  /** Size in new APK (0 if removed) */
  newSize: number;
  /** Size difference (positive = larger, negative = smaller) */
  difference: number;
  /** Change status */
  status: CompareEntryStatus;
  /** Whether this is a directory entry */
  isDirectory: boolean;
}

export interface CompareSummary {
  /** Total size of old APK */
  oldTotal: number;
  /** Total size of new APK */
  newTotal: number;
  /** Total size difference */
  totalDifference: number;
  /** Number of files in old APK */
  oldFileCount: number;
  /** Number of files in new APK */
  newFileCount: number;
  /** Number of added files */
  addedCount: number;
  /** Number of removed files */
  removedCount: number;
  /** Number of modified files */
  modifiedCount: number;
  /** Number of unchanged files */
  unchangedCount: number;
}

export interface CategoryBreakdown {
  /** Category name (dex, resources, native, assets, other) */
  category: string;
  /** Size in old APK */
  oldSize: number;
  /** Size in new APK */
  newSize: number;
  /** Size difference */
  difference: number;
  /** Number of files in this category */
  fileCount: number;
  /** Number of added files */
  addedCount: number;
  /** Number of removed files */
  removedCount: number;
  /** Number of modified files */
  modifiedCount: number;
}

export interface CompareResult {
  /** Summary statistics */
  summary: CompareSummary;
  /** Category breakdown (if requested) */
  breakdown?: CategoryBreakdown[];
  /** Individual file entries */
  entries: CompareEntry[];
}

export interface CompareOptions {
  /** Only show files with differences (exclude unchanged) */
  differentOnly?: boolean;
  /** Don't show directory entries */
  filesOnly?: boolean;
  /** Sort by size difference (largest first) */
  sortByDiff?: boolean;
  /** Include category breakdown */
  breakdown?: boolean;
  /** Include estimated patch sizes for delta updates */
  patchSize?: boolean;
  /** Filter by file category (dex, native, resources, assets, other) */
  category?: 'dex' | 'native' | 'resources' | 'assets' | 'other';
  /** Only show added files */
  addedOnly?: boolean;
  /** Only show removed files */
  removedOnly?: boolean;
  /** Only show modified files */
  modifiedOnly?: boolean;
  /** Filter by minimum absolute size difference in bytes */
  minDifference?: number;
  /** Limit number of entries returned */
  limit?: number;
  /** Timeout in milliseconds (default: 120000) */
  timeout?: number;
}

// ============================================================================
// Error Class
// ============================================================================

export class ApkAnalyzerError extends Error {
  constructor(
    message: string,
    public readonly code: number,
    public readonly stderr: string
  ) {
    super(message);
    this.name = 'ApkAnalyzerError';
  }
}

// ============================================================================
// Binary Resolution
// ============================================================================

/**
 * Get the platform-specific binary name
 */
function getPlatformDir(): string {
  const p = platform();
  const a = arch();

  if (p === 'linux' && a === 'x64') return 'linux-x64';
  if (p === 'linux' && a === 'arm64') return 'linux-arm64';
  if (p === 'darwin' && a === 'x64') return 'darwin-x64';
  if (p === 'darwin' && a === 'arm64') return 'darwin-arm64';
  if (p === 'win32' && a === 'x64') return 'win32-x64';

  throw new Error(`Unsupported platform: ${p}-${a}`);
}

/**
 * Get the path to the apk-analyzer binary
 */
function getBinaryPath(): string {
  const platformDir = getPlatformDir();
  const binaryName = platform() === 'win32' ? 'apk-analyzer.exe' : 'apk-analyzer';

  // Check multiple possible locations
  const possiblePaths = [
    // npm package (binaries directory)
    join(__dirname, '..', 'binaries', platformDir, binaryName),
    // Development (parent dist directory)
    join(__dirname, '..', '..', 'dist', platformDir, binaryName),
    // Legacy location
    join(__dirname, '..', 'dist', platformDir, binaryName),
    // Zig build output
    join(__dirname, '..', '..', 'zig-out', 'bin', binaryName),
  ];

  for (const p of possiblePaths) {
    if (existsSync(p)) {
      return p;
    }
  }

  throw new Error(
    `APK Analyzer binary not found for ${platformDir}. ` +
      `Searched: ${possiblePaths.join(', ')}. ` +
      `Please ensure the package is properly installed.`
  );
}

// ============================================================================
// Main API
// ============================================================================

/**
 * Analyze an APK or AAB file
 *
 * @param filePath - Path to the APK or AAB file
 * @param options - Analysis options
 * @returns Analysis result
 *
 * @example
 * ```typescript
 * const result = await analyzeApk('/path/to/app.apk');
 * console.log(`Package: ${result.packageId}`);
 * console.log(`Version: ${result.versionName} (${result.versionCode})`);
 * console.log(`Size: ${result.compressedSize} bytes`);
 * ```
 */
export async function analyzeApk(
  filePath: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisResult> {
  const binaryPath = getBinaryPath();
  const args: string[] = [filePath, '--streaming', '--compact', '--quiet'];

  if (options.fast) {
    args.push('--fast');
  } else {
    if (options.skipDex) args.push('--skip-dex');
    if (options.skipCert) args.push('--skip-cert');
  }

  const timeout = options.timeout ?? 60000;

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    const proc = spawn(binaryPath, args, {
      timeout,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on('error', (err) => {
      reject(new ApkAnalyzerError(`Failed to spawn apk-analyzer: ${err.message}`, -1, stderr));
    });

    proc.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout) as AnalysisResult;
          resolve(result);
        } catch (parseErr) {
          reject(
            new ApkAnalyzerError(
              `Failed to parse apk-analyzer output: ${parseErr}`,
              code ?? -1,
              stderr
            )
          );
        }
      } else {
        const exitCode = code ?? -1;
        let message = `apk-analyzer exited with code ${exitCode}`;

        switch (exitCode) {
          case 1:
            message = 'Invalid arguments';
            break;
          case 2:
            message = `File not found or read error: ${filePath}`;
            break;
          case 3:
            message = 'Analysis error: Invalid APK/AAB file';
            break;
        }

        reject(new ApkAnalyzerError(message, exitCode, stderr));
      }
    });
  });
}

/**
 * Check if the apk-analyzer binary is available for the current platform
 */
export function isAvailable(): boolean {
  try {
    getBinaryPath();
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the version of the apk-analyzer CLI
 */
export async function getVersion(): Promise<string> {
  const binaryPath = getBinaryPath();

  return new Promise((resolve, reject) => {
    let stdout = '';

    const proc = spawn(binaryPath, ['--version'], {
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.on('error', (err) => {
      reject(new Error(`Failed to get version: ${err.message}`));
    });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve(stdout.trim().replace('apk-analyzer ', ''));
      } else {
        reject(new Error(`Failed to get version: exit code ${code}`));
      }
    });
  });
}

/**
 * Compare two APK files and return the differences
 *
 * @param oldFilePath - Path to the old/baseline APK file
 * @param newFilePath - Path to the new APK file
 * @param options - Comparison options
 * @returns Comparison result with summary and file-level differences
 *
 * @example
 * ```typescript
 * const diff = await compareApks('/path/to/v1.apk', '/path/to/v2.apk', {
 *   differentOnly: true,
 *   breakdown: true,
 * });
 *
 * console.log(`Size change: ${diff.summary.totalDifference} bytes`);
 * console.log(`Added: ${diff.summary.addedCount} files`);
 * console.log(`Removed: ${diff.summary.removedCount} files`);
 * console.log(`Modified: ${diff.summary.modifiedCount} files`);
 *
 * // Show breakdown by category
 * if (diff.breakdown) {
 *   for (const cat of diff.breakdown) {
 *     console.log(`${cat.category}: ${cat.difference} bytes`);
 *   }
 * }
 *
 * // Filter by category and status
 * const dexChanges = await compareApks(oldApk, newApk, {
 *   category: 'dex',
 *   modifiedOnly: true,
 * });
 *
 * // Get top 10 largest changes
 * const topChanges = await compareApks(oldApk, newApk, {
 *   differentOnly: true,
 *   sortByDiff: true,
 *   limit: 10,
 * });
 * ```
 */
export async function compareApks(
  oldFilePath: string,
  newFilePath: string,
  options: CompareOptions = {}
): Promise<CompareResult> {
  const binaryPath = getBinaryPath();
  const args: string[] = ['compare', oldFilePath, newFilePath, '--compact', '--quiet'];

  if (options.differentOnly) args.push('--different-only');
  if (options.filesOnly) args.push('--files-only');
  if (options.sortByDiff) args.push('--sort-by-diff');
  if (options.breakdown) args.push('--breakdown');
  if (options.patchSize) args.push('--patch-size');
  if (options.addedOnly) args.push('--added-only');
  if (options.removedOnly) args.push('--removed-only');
  if (options.modifiedOnly) args.push('--modified-only');
  if (options.category) {
    args.push('--category', options.category);
  }
  if (options.minDifference !== undefined) {
    args.push('--min-diff', options.minDifference.toString());
  }
  if (options.limit !== undefined) {
    args.push('--limit', options.limit.toString());
  }

  const timeout = options.timeout ?? 120000;

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    const proc = spawn(binaryPath, args, {
      timeout,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on('error', (err) => {
      reject(new ApkAnalyzerError(`Failed to spawn apk-analyzer: ${err.message}`, -1, stderr));
    });

    proc.on('close', (code) => {
      if (code === 0) {
        try {
          const rawResult = JSON.parse(stdout);
          // Transform the raw result to match our interface
          const result: CompareResult = {
            summary: rawResult.summary,
            breakdown: rawResult.breakdown,
            entries: rawResult.entries,
          };
          resolve(result);
        } catch (parseErr) {
          reject(
            new ApkAnalyzerError(
              `Failed to parse apk-analyzer output: ${parseErr}`,
              code ?? -1,
              stderr
            )
          );
        }
      } else {
        const exitCode = code ?? -1;
        let message = `apk-analyzer exited with code ${exitCode}`;

        switch (exitCode) {
          case 1:
            message = 'Invalid arguments';
            break;
          case 2:
            message = `File not found or read error`;
            break;
          case 3:
            message = 'Comparison error: Invalid APK file';
            break;
        }

        reject(new ApkAnalyzerError(message, exitCode, stderr));
      }
    });
  });
}

// Default export
export default { analyzeApk, compareApks, isAvailable, getVersion };
