#!/usr/bin/env node

/**
 * Smart Contract Security Auditor
 * 
 * A TypeScript-based security analyzer for detecting vulnerabilities
 * in Solidity smart contracts.
 * 
 * Usage:
 *   npx ts-node src/index.ts <path-to-contract-or-directory>
 *   node dist/index.js <path-to-contract-or-directory>
 */

import * as path from 'path';
import * as fs from 'fs';
import {
  SmartContractAnalyzer,
  createAnalyzer,
  analyzeContracts,
  AnalysisReport,
  AnalyzerOptions
} from './analyzer';
import {
  formatAnalysisResults,
  formatSummary,
  generateSummary,
  readDirectory,
  getContractName
} from './utils';
import {
  VulnerabilityType,
  Severity,
  getAllVulnerabilityTypes,
  getAllSeverityLevels
} from './patterns';

interface CliOptions {
  help: boolean;
  version: boolean;
  output: string;
  exclude: string[];
  severity: Severity | 'all';
  recursive: boolean;
  quiet: boolean;
  json: boolean;
}

const VERSION = '1.0.0';

function printBanner(): void {
  console.log('\x1b[36m');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║     SMART CONTRACT SECURITY AUDITOR v' + VERSION + '              ║');
  console.log('║     Detect vulnerabilities in Solidity smart contracts    ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('\x1b[0m');
}

function printHelp(): void {
  console.log(`
Smart Contract Security Auditor - Security analysis for Solidity contracts

USAGE:
  smart-contract-auditor <path> [options]

ARGUMENTS:
  path                  Path to Solidity file or directory to analyze

OPTIONS:
  -h, --help            Show this help message
  -v, --version         Show version number
  -o, --output <file>   Write results to file instead of stdout
  -e, --exclude <type>  Exclude vulnerability type (can be used multiple times)
  -s, --severity <lvl>  Minimum severity level: critical, high, medium, low, info
  -r, --recursive       Recursively scan directories
  -q, --quiet           Suppress banner and summary output
  -j, --json            Output results as JSON

EXAMPLES:
  smart-contract-auditor ./contracts/MyToken.sol
  smart-contract-auditor ./contracts/ -r -s high
  smart-contract-auditor ./src/ --exclude reentrancy --json

SUPPORTED VULNERABILITY TYPES:
  - reentrancy              Reentrancy attacks
  - integer_overflow        Integer overflow issues
  - integer_underflow       Integer underflow issues
  - unchecked_external_call Unchecked call return values
  - access_control          Missing access control
  - timestamp_dependence    Block timestamp manipulation
  - front_running           Front-running vulnerabilities
  - denial_of_service       Potential DoS attacks
  - unprotected_function    Unprotected critical functions
  - weak_randomness         Insecure randomness
  - deprecated_function     Deprecated Solidity functions
  - uninitialized_variable  Uninitialized storage pointers

SEVERITY LEVELS:
  critical    Issues that can lead to complete loss of funds
  high        Significant security issues
  medium      Moderate security concerns
  low         Minor issues or best practice violations
  info        Informational findings
`);
}

function parseArgs(args: string[]): { target: string | null; options: CliOptions } {
  const options: CliOptions = {
    help: false,
    version: false,
    output: '',
    exclude: [],
    severity: 'all',
    recursive: false,
    quiet: false,
    json: false
  };
  
  let target: string | null = null;
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '-h' || arg === '--help') {
      options.help = true;
    } else if (arg === '-v' || arg === '--version') {
      options.version = true;
    } else if (arg === '-o' || arg === '--output') {
      options.output = args[++i] || '';
    } else if (arg === '-e' || arg === '--exclude') {
      const excludeType = args[++i] || '';
      if (excludeType) {
        options.exclude.push(excludeType);
      }
    } else if (arg === '-s' || arg === '--severity') {
      const severity = args[++i] || 'all';
      options.severity = severity as Severity | 'all';
    } else if (arg === '-r' || arg === '--recursive') {
      options.recursive = true;
    } else if (arg === '-q' || arg === '--quiet') {
      options.quiet = true;
    } else if (arg === '-j' || arg === '--json') {
      options.json = true;
    } else if (!arg.startsWith('-') && !target) {
      target = arg;
    }
  }
  
  return { target, options };
}

function validateSeverity(severity: string): boolean {
  const validSeverities = getAllSeverityLevels().map(s => s.toLowerCase());
  return validSeverities.includes(severity.toLowerCase()) || severity === 'all';
}

function filterBySeverity(
  report: AnalysisReport,
  minSeverity: Severity | 'all'
): AnalysisReport {
  if (minSeverity === 'all') {
    return report;
  }
  
  const severityOrder: Record<Severity, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 1,
    [Severity.Medium]: 2,
    [Severity.Low]: 3,
    [Severity.Info]: 4
  };
  
  const minLevel = severityOrder[minSeverity as Severity];
  
  const filteredFiles = report.files.map(file => ({
    ...file,
    results: file.results.filter(r => severityOrder[r.severity] <= minLevel)
  }));
  
  const totalIssues = filteredFiles.reduce((sum, f) => sum + f.results.length, 0);
  
  return {
    ...report,
    files: filteredFiles,
    totalIssues
  };
}

function collectFiles(target: string, recursive: boolean): string[] {
  const resolvedPath = path.resolve(target);
  
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${resolvedPath}`);
  }
  
  const stats = fs.statSync(resolvedPath);
  
  if (stats.isFile()) {
    if (!resolvedPath.endsWith('.sol')) {
      throw new Error('File must have .sol extension');
    }
    return [resolvedPath];
  }
  
  if (stats.isDirectory()) {
    if (recursive) {
      return readDirectory(resolvedPath, '.sol');
    } else {
      const entries = fs.readdirSync(resolvedPath);
      return entries
        .filter(e => e.endsWith('.sol'))
        .map(e => path.join(resolvedPath, e));
    }
  }
  
  return [];
}

function runAnalysis(target: string, options: CliOptions): void {
  const files = collectFiles(target, options.recursive);
  
  if (files.length === 0) {
    console.log('\x1b[33mNo Solidity files found to analyze.\x1b[0m');
    return;
  }
  
  const analyzerOptions: AnalyzerOptions = {
    excludePatterns: options.exclude as VulnerabilityType[],
    includeWarnings: options.severity === 'all' || options.severity === 'info'
  };
  
  const analyzer = createAnalyzer(analyzerOptions);
  let report = analyzer.analyzeFiles(files);
  
  if (options.severity !== 'all') {
    report = filterBySeverity(report, options.severity as Severity);
  }
  
  let output: string;
  
  if (options.json) {
    output = JSON.stringify(report, null, 2);
  } else {
    output = formatAnalysisResults(report.files.flatMap(f => f.results));
    
    if (!options.quiet) {
      const summary = generateSummary(report.files.flatMap(f => f.results));
      output += formatSummary(summary);
    }
  }
  
  if (options.output) {
    fs.writeFileSync(path.resolve(options.output), output);
    console.log(`\x1b[32mResults written to: ${options.output}\x1b[0m`);
  } else {
    console.log(output);
  }
  
  process.exit(report.totalIssues > 0 ? 1 : 0);
}

function main(): void {
  const args = process.argv.slice(2);
  const { target, options } = parseArgs(args);
  
  if (options.help) {
    printHelp();
    process.exit(0);
  }
  
  if (options.version) {
    console.log(`smart-contract-auditor v${VERSION}`);
    process.exit(0);
  }
  
  if (!target) {
    printBanner();
    console.log('\x1b[31mError: No target file or directory specified.\x1b[0m');
    console.log('Use --help for usage information.');
    process.exit(1);
  }
  
  if (options.exclude.length > 0) {
    const validTypes = getAllVulnerabilityTypes().map(t => t.toLowerCase());
    for (const exclude of options.exclude) {
      if (!validTypes.includes(exclude.toLowerCase())) {
        console.log(`\x1b[33mWarning: Unknown vulnerability type: ${exclude}\x1b[0m`);
      }
    }
  }
  
  if (!validateSeverity(options.severity)) {
    console.log(`\x1b[31mError: Invalid severity level: ${options.severity}\x1b[0m`);
    console.log('Valid levels: critical, high, medium, low, info, all');
    process.exit(1);
  }
  
  if (!options.quiet) {
    printBanner();
  }
  
  try {
    runAnalysis(target, options);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.log(`\x1b[31mError: ${message}\x1b[0m`);
    process.exit(1);
  }
}

export {
  SmartContractAnalyzer,
  createAnalyzer,
  analyzeContracts,
  VulnerabilityType,
  Severity,
  AnalysisReport,
  AnalyzerOptions
};

if (require.main === module) {
  main();
}
