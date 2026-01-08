#!/usr/bin/env node
"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Severity = exports.VulnerabilityType = exports.analyzeContracts = exports.createAnalyzer = exports.SmartContractAnalyzer = void 0;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const analyzer_1 = require("./analyzer");
Object.defineProperty(exports, "SmartContractAnalyzer", { enumerable: true, get: function () { return analyzer_1.SmartContractAnalyzer; } });
Object.defineProperty(exports, "createAnalyzer", { enumerable: true, get: function () { return analyzer_1.createAnalyzer; } });
Object.defineProperty(exports, "analyzeContracts", { enumerable: true, get: function () { return analyzer_1.analyzeContracts; } });
const utils_1 = require("./utils");
const patterns_1 = require("./patterns");
Object.defineProperty(exports, "VulnerabilityType", { enumerable: true, get: function () { return patterns_1.VulnerabilityType; } });
Object.defineProperty(exports, "Severity", { enumerable: true, get: function () { return patterns_1.Severity; } });
const VERSION = '1.0.0';
function printBanner() {
    console.log('\x1b[36m');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║     SMART CONTRACT SECURITY AUDITOR v' + VERSION + '              ║');
    console.log('║     Detect vulnerabilities in Solidity smart contracts    ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('\x1b[0m');
}
function printHelp() {
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
function parseArgs(args) {
    const options = {
        help: false,
        version: false,
        output: '',
        exclude: [],
        severity: 'all',
        recursive: false,
        quiet: false,
        json: false
    };
    let target = null;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '-h' || arg === '--help') {
            options.help = true;
        }
        else if (arg === '-v' || arg === '--version') {
            options.version = true;
        }
        else if (arg === '-o' || arg === '--output') {
            options.output = args[++i] || '';
        }
        else if (arg === '-e' || arg === '--exclude') {
            const excludeType = args[++i] || '';
            if (excludeType) {
                options.exclude.push(excludeType);
            }
        }
        else if (arg === '-s' || arg === '--severity') {
            const severity = args[++i] || 'all';
            options.severity = severity;
        }
        else if (arg === '-r' || arg === '--recursive') {
            options.recursive = true;
        }
        else if (arg === '-q' || arg === '--quiet') {
            options.quiet = true;
        }
        else if (arg === '-j' || arg === '--json') {
            options.json = true;
        }
        else if (!arg.startsWith('-') && !target) {
            target = arg;
        }
    }
    return { target, options };
}
function validateSeverity(severity) {
    const validSeverities = (0, patterns_1.getAllSeverityLevels)().map(s => s.toLowerCase());
    return validSeverities.includes(severity.toLowerCase()) || severity === 'all';
}
function filterBySeverity(report, minSeverity) {
    if (minSeverity === 'all') {
        return report;
    }
    const severityOrder = {
        [patterns_1.Severity.Critical]: 0,
        [patterns_1.Severity.High]: 1,
        [patterns_1.Severity.Medium]: 2,
        [patterns_1.Severity.Low]: 3,
        [patterns_1.Severity.Info]: 4
    };
    const minLevel = severityOrder[minSeverity];
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
function collectFiles(target, recursive) {
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
            return (0, utils_1.readDirectory)(resolvedPath, '.sol');
        }
        else {
            const entries = fs.readdirSync(resolvedPath);
            return entries
                .filter(e => e.endsWith('.sol'))
                .map(e => path.join(resolvedPath, e));
        }
    }
    return [];
}
function runAnalysis(target, options) {
    const files = collectFiles(target, options.recursive);
    if (files.length === 0) {
        console.log('\x1b[33mNo Solidity files found to analyze.\x1b[0m');
        return;
    }
    const analyzerOptions = {
        excludePatterns: options.exclude,
        includeWarnings: options.severity === 'all' || options.severity === 'info'
    };
    const analyzer = (0, analyzer_1.createAnalyzer)(analyzerOptions);
    let report = analyzer.analyzeFiles(files);
    if (options.severity !== 'all') {
        report = filterBySeverity(report, options.severity);
    }
    let output;
    if (options.json) {
        output = JSON.stringify(report, null, 2);
    }
    else {
        output = (0, utils_1.formatAnalysisResults)(report.files.flatMap(f => f.results));
        if (!options.quiet) {
            const summary = (0, utils_1.generateSummary)(report.files.flatMap(f => f.results));
            output += (0, utils_1.formatSummary)(summary);
        }
    }
    if (options.output) {
        fs.writeFileSync(path.resolve(options.output), output);
        console.log(`\x1b[32mResults written to: ${options.output}\x1b[0m`);
    }
    else {
        console.log(output);
    }
    process.exit(report.totalIssues > 0 ? 1 : 0);
}
function main() {
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
        const validTypes = (0, patterns_1.getAllVulnerabilityTypes)().map(t => t.toLowerCase());
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
    }
    catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.log(`\x1b[31mError: ${message}\x1b[0m`);
        process.exit(1);
    }
}
if (require.main === module) {
    main();
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFFQTs7Ozs7Ozs7O0dBU0c7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUVILDJDQUE2QjtBQUM3Qix1Q0FBeUI7QUFDekIseUNBTW9CO0FBa1NsQixzR0F2U0EsZ0NBQXFCLE9BdVNBO0FBQ3JCLCtGQXZTQSx5QkFBYyxPQXVTQTtBQUNkLGlHQXZTQSwyQkFBZ0IsT0F1U0E7QUFuU2xCLG1DQU1pQjtBQUNqQix5Q0FLb0I7QUF3UmxCLGtHQTVSQSw0QkFBaUIsT0E0UkE7QUFDakIseUZBNVJBLG1CQUFRLE9BNFJBO0FBNVFWLE1BQU0sT0FBTyxHQUFHLE9BQU8sQ0FBQztBQUV4QixTQUFTLFdBQVc7SUFDbEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN4QixPQUFPLENBQUMsR0FBRyxDQUFDLCtEQUErRCxDQUFDLENBQUM7SUFDN0UsT0FBTyxDQUFDLEdBQUcsQ0FBQyx5Q0FBeUMsR0FBRyxPQUFPLEdBQUcsaUJBQWlCLENBQUMsQ0FBQztJQUNyRixPQUFPLENBQUMsR0FBRyxDQUFDLCtEQUErRCxDQUFDLENBQUM7SUFDN0UsT0FBTyxDQUFDLEdBQUcsQ0FBQywrREFBK0QsQ0FBQyxDQUFDO0lBQzdFLE9BQU8sQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLENBQUM7QUFDekIsQ0FBQztBQUVELFNBQVMsU0FBUztJQUNoQixPQUFPLENBQUMsR0FBRyxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztDQTRDYixDQUFDLENBQUM7QUFDSCxDQUFDO0FBRUQsU0FBUyxTQUFTLENBQUMsSUFBYztJQUMvQixNQUFNLE9BQU8sR0FBZTtRQUMxQixJQUFJLEVBQUUsS0FBSztRQUNYLE9BQU8sRUFBRSxLQUFLO1FBQ2QsTUFBTSxFQUFFLEVB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QUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNsQixDQUFDO0FBQ0gsQ0FBQztBQVlELElBQUksT0FBTyxDQUFDLElBQUksS0FBSyxNQUFNLEVBQUUsQ0FBQztJQUM1QixJQUFJLEVBQUUsQ0FBQztBQUNULENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIjIS91c3IvYmluL2VudiBub2RlXG5cbi8qKlxuICogU21hcnQgQ29udHJhY3QgU2VjdXJpdHkgQXVkaXRvclxuICogXG4gKiBBIFR5cGVTY3JpcHQtYmFzZWQgc2VjdXJpdHkgYW5hbHl6ZXIgZm9yIGRldGVjdGluZyB2dWxuZXJhYmlsaXRpZXNcbiAqIGluIFNvbGlkaXR5IHNtYXJ0IGNvbnRyYWN0cy5cbiAqIFxuICogVXNhZ2U6XG4gKiAgIG5weCB0cy1ub2RlIHNyYy9pbmRleC50cyA8cGF0aC10by1jb250cmFjdC1vci1kaXJlY3Rvcnk+XG4gKiAgIG5vZGUgZGlzdC9pbmRleC5qcyA8cGF0aC10by1jb250cmFjdC1vci1kaXJlY3Rvcnk+XG4gKi9cblxuaW1wb3J0ICogYXMgcGF0aCBmcm9tICdwYXRoJztcbmltcG9ydCAqIGFzIGZzIGZyb20gJ2ZzJztcbmltcG9ydCB7XG4gIFNtYXJ0Q29udHJhY3RBbmFseXplcixcbiAgY3JlYXRlQW5hbHl6ZXIsXG4gIGFuYWx5emVDb250cmFjdHMsXG4gIEFuYWx5c2lzUmVwb3J0LFxuICBBbmFseXplck9wdGlvbnNcbn0gZnJvbSAnLi9hbmFseXplcic7XG5pbXBvcnQge1xuICBmb3JtYXRBbmFseXNpc1Jlc3VsdHMsXG4gIGZvcm1hdFN1bW1hcnksXG4gIGdlbmVyYXRlU3VtbWFyeSxcbiAgcmVhZERpcmVjdG9yeSxcbiAgZ2V0Q29udHJhY3ROYW1lXG59IGZyb20gJy4vdXRpbHMnO1xuaW1wb3J0IHtcbiAgVnVsbmVyYWJpbGl0eVR5cGUsXG4gIFNldmVyaXR5LFxuICBnZXRBbGxWdWxuZXJhYmlsaXR5VHlwZXMsXG4gIGdldEFsbFNldmVyaXR5TGV2ZWxzXG59IGZyb20gJy4vcGF0dGVybnMnO1xuXG5pbnRlcmZhY2UgQ2xpT3B0aW9ucyB7XG4gIGhlbHA6IGJvb2xlYW47XG4gIHZlcnNpb246IGJvb2xlYW47XG4gIG91dHB1dDogc3RyaW5nO1xuICBleGNsdWRlOiBzdHJpbmdbXTtcbiAgc2V2ZXJpdHk6IFNldmVyaXR5IHwgJ2FsbCc7XG4gIHJlY3Vyc2l2ZTogYm9vbGVhbjtcbiAgcXVpZXQ6IGJvb2xlYW47XG4gIGpzb246IGJvb2xlYW47XG59XG5cbmNvbnN0IFZFUlNJT04gPSAnMS4wLjAnO1xuXG5mdW5jdGlvbiBwcmludEJhbm5lcigpOiB2b2lkIHtcbiAgY29uc29sZS5sb2coJ1xceDFiWzM2bScpO1xuICBjb25zb2xlLmxvZygn4pWU4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWXJyk7XG4gIGNvbnNvbGUubG9nKCfilZEgICAgIFNNQVJUIENPTlRSQUNUIFNFQ1VSSVRZIEFVRElUT1IgdicgKyBWRVJTSU9OICsgJyAgICAgICAgICAgICAg4pWRJyk7XG4gIGNvbnNvbGUubG9nKCfilZEgICAgIERldGVjdCB2dWxuZXJhYmlsaXRpZXMgaW4gU29saWRpdHkgc21hcnQgY29udHJhY3RzICAgIOKVkScpO1xuICBjb25zb2xlLmxvZygn4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWQ4pWdJyk7XG4gIGNvbnNvbGUubG9nKCdcXHgxYlswbScpO1xufVxuXG5mdW5jdGlvbiBwcmludEhlbHAoKTogdm9pZCB7XG4gIGNvbnNvbGUubG9nKGBcblNtYXJ0IENvbnRyYWN0IFNlY3VyaXR5IEF1ZGl0b3IgLSBTZWN1cml0eSBhbmFseXNpcyBmb3IgU29saWRpdHkgY29udHJhY3RzXG5cblVTQUdFOlxuICBzbWFydC1jb250cmFjdC1hdWRpdG9yIDxwYXRoPiBbb3B0aW9uc11cblxuQVJHVU1FTlRTOlxuICBwYXRoICAgICAgICAgICAgICAgICAgUGF0aCB0byBTb2xpZGl0eSBmaWxlIG9yIGRpcmVjdG9yeSB0byBhbmFseXplXG5cbk9QVElPTlM6XG4gIC1oLCAtLWhlbHAgICAgICAgICAgICBTaG93IHRoaXMgaGVscCBtZXNzYWdlXG4gIC12LCAtLXZlcnNpb24gICAgICAgICBTaG93IHZlcnNpb24gbnVtYmVyXG4gIC1vLCAtLW91dHB1dCA8ZmlsZT4gICBXcml0ZSByZXN1bHRzIHRvIGZpbGUgaW5zdGVhZCBvZiBzdGRvdXRcbiAgLWUsIC0tZXhjbHVkZSA8dHlwZT4gIEV4Y2x1ZGUgdnVsbmVyYWJpbGl0eSB0eXBlIChjYW4gYmUgdXNlZCBtdWx0aXBsZSB0aW1lcylcbiAgLXMsIC0tc2V2ZXJpdHkgPGx2bD4gIE1pbmltdW0gc2V2ZXJpdHkgbGV2ZWw6IGNyaXRpY2FsLCBoaWdoLCBtZWRpdW0sIGxvdywgaW5mb1xuICAtciwgLS1yZWN1cnNpdmUgICAgICAgUmVjdXJzaXZlbHkgc2NhbiBkaXJlY3Rvcmllc1xuICAtcSwgLS1xdWlldCAgICAgICAgICAgU3VwcHJlc3MgYmFubmVyIGFuZCBzdW1tYXJ5IG91dHB1dFxuICAtaiwgLS1qc29uICAgICAgICAgICAgT3V0cHV0IHJlc3VsdHMgYXMgSlNPTlxuXG5FWEFNUExFUzpcbiAgc21hcnQtY29udHJhY3QtYXVkaXRvciAuL2NvbnRyYWN0cy9NeVRva2VuLnNvbFxuICBzbWFydC1jb250cmFjdC1hdWRpdG9yIC4vY29udHJhY3RzLyAtciAtcyBoaWdoXG4gIHNtYXJ0LWNvbnRyYWN0LWF1ZGl0b3IgLi9zcmMvIC0tZXhjbHVkZSByZWVudHJhbmN5IC0tanNvblxuXG5TVVBQT1JURUQgVlVMTkVSQUJJTElUWSBUWVBFUzpcbiAgLSByZWVudHJhbmN5ICAgICAgICAgICAgICBSZWVudHJhbmN5IGF0dGFja3NcbiAgLSBpbnRlZ2VyX292ZXJmbG93ICAgICAgICBJbnRlZ2VyIG92ZXJmbG93IGlzc3Vlc1xuICAtIGludGVnZXJfdW5kZXJmbG93ICAgICAgIEludGVnZXIgdW5kZXJmbG93IGlzc3Vlc1xuICAtIHVuY2hlY2tlZF9leHRlcm5hbF9jYWxsIFVuY2hlY2tlZCBjYWxsIHJldHVybiB2YWx1ZXNcbiAgLSBhY2Nlc3NfY29udHJvbCAgICAgICAgICBNaXNzaW5nIGFjY2VzcyBjb250cm9sXG4gIC0gdGltZXN0YW1wX2RlcGVuZGVuY2UgICAgQmxvY2sgdGltZXN0YW1wIG1hbmlwdWxhdGlvblxuICAtIGZyb250X3J1bm5pbmcgICAgICAgICAgIEZyb250LXJ1bm5pbmcgdnVsbmVyYWJpbGl0aWVzXG4gIC0gZGVuaWFsX29mX3NlcnZpY2UgICAgICAgUG90ZW50aWFsIERvUyBhdHRhY2tzXG4gIC0gdW5wcm90ZWN0ZWRfZnVuY3Rpb24gICAgVW5wcm90ZWN0ZWQgY3JpdGljYWwgZnVuY3Rpb25zXG4gIC0gd2Vha19yYW5kb21uZXNzICAgICAgICAgSW5zZWN1cmUgcmFuZG9tbmVzc1xuICAtIGRlcHJlY2F0ZWRfZnVuY3Rpb24gICAgIERlcHJlY2F0ZWQgU29saWRpdHkgZnVuY3Rpb25zXG4gIC0gdW5pbml0aWFsaXplZF92YXJpYWJsZSAgVW5pbml0aWFsaXplZCBzdG9yYWdlIHBvaW50ZXJzXG5cblNFVkVSSVRZIExFVkVMUzpcbiAgY3JpdGljYWwgICAgSXNzdWVzIHRoYXQgY2FuIGxlYWQgdG8gY29tcGxldGUgbG9zcyBvZiBmdW5kc1xuICBoaWdoICAgICAgICBTaWduaWZpY2FudCBzZWN1cml0eSBpc3N1ZXNcbiAgbWVkaXVtICAgICAgTW9kZXJhdGUgc2VjdXJpdHkgY29uY2VybnNcbiAgbG93ICAgICAgICAgTWlub3IgaXNzdWVzIG9yIGJlc3QgcHJhY3RpY2UgdmlvbGF0aW9uc1xuICBpbmZvICAgICAgICBJbmZvcm1hdGlvbmFsIGZpbmRpbmdzXG5gKTtcbn1cblxuZnVuY3Rpb24gcGFyc2VBcmdzKGFyZ3M6IHN0cmluZ1tdKTogeyB0YXJnZXQ6IHN0cmluZyB8IG51bGw7IG9wdGlvbnM6IENsaU9wdGlvbnMgfSB7XG4gIGNvbnN0IG9wdGlvbnM6IENsaU9wdGlvbnMgPSB7XG4gICAgaGVscDogZmFsc2UsXG4gICAgdmVyc2lvbjogZmFsc2UsXG4gICAgb3V0cHV0OiAnJyxcbiAgICBleGNsdWRlOiBbXSxcbiAgICBzZXZlcml0eTogJ2FsbCcsXG4gICAgcmVjdXJzaXZlOiBmYWxzZSxcbiAgICBxdWlldDogZmFsc2UsXG4gICAganNvbjogZmFsc2VcbiAgfTtcbiAgXG4gIGxldCB0YXJnZXQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICBcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBhcmdzLmxlbmd0aDsgaSsrKSB7XG4gICAgY29uc3QgYXJnID0gYXJnc1tpXTtcbiAgICBcbiAgICBpZiAoYXJnID09PSAnLWgnIHx8IGFyZyA9PT0gJy0taGVscCcpIHtcbiAgICAgIG9wdGlvbnMuaGVscCA9IHRydWU7XG4gICAgfSBlbHNlIGlmIChhcmcgPT09ICctdicgfHwgYXJnID09PSAnLS12ZXJzaW9uJykge1xuICAgICAgb3B0aW9ucy52ZXJzaW9uID0gdHJ1ZTtcbiAgICB9IGVsc2UgaWYgKGFyZyA9PT0gJy1vJyB8fCBhcmcgPT09ICctLW91dHB1dCcpIHtcbiAgICAgIG9wdGlvbnMub3V0cHV0ID0gYXJnc1srK2ldIHx8ICcnO1xuICAgIH0gZWxzZSBpZiAoYXJnID09PSAnLWUnIHx8IGFyZyA9PT0gJy0tZXhjbHVkZScpIHtcbiAgICAgIGNvbnN0IGV4Y2x1ZGVUeXBlID0gYXJnc1srK2ldIHx8ICcnO1xuICAgICAgaWYgKGV4Y2x1ZGVUeXBlKSB7XG4gICAgICAgIG9wdGlvbnMuZXhjbHVkZS5wdXNoKGV4Y2x1ZGVUeXBlKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKGFyZyA9PT0gJy1zJyB8fCBhcmcgPT09ICctLXNldmVyaXR5Jykge1xuICAgICAgY29uc3Qgc2V2ZXJpdHkgPSBhcmdzWysraV0gfHwgJ2FsbCc7XG4gICAgICBvcHRpb25zLnNldmVyaXR5ID0gc2V2ZXJpdHkgYXMgU2V2ZXJpdHkgfCAnYWxsJztcbiAgICB9IGVsc2UgaWYgKGFyZyA9PT0gJy1yJyB8fCBhcmcgPT09ICctLXJlY3Vyc2l2ZScpIHtcbiAgICAgIG9wdGlvbnMucmVjdXJzaXZlID0gdHJ1ZTtcbiAgICB9IGVsc2UgaWYgKGFyZyA9PT0gJy1xJyB8fCBhcmcgPT09ICctLXF1aWV0Jykge1xuICAgICAgb3B0aW9ucy5xdWlldCA9IHRydWU7XG4gICAgfSBlbHNlIGlmIChhcmcgPT09ICctaicgfHwgYXJnID09PSAnLS1qc29uJykge1xuICAgICAgb3B0aW9ucy5qc29uID0gdHJ1ZTtcbiAgICB9IGVsc2UgaWYgKCFhcmcuc3RhcnRzV2l0aCgnLScpICYmICF0YXJnZXQpIHtcbiAgICAgIHRhcmdldCA9IGFyZztcbiAgICB9XG4gIH1cbiAgXG4gIHJldHVybiB7IHRhcmdldCwgb3B0aW9ucyB9O1xufVxuXG5mdW5jdGlvbiB2YWxpZGF0ZVNldmVyaXR5KHNldmVyaXR5OiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgdmFsaWRTZXZlcml0aWVzID0gZ2V0QWxsU2V2ZXJpdHlMZXZlbHMoKS5tYXAocyA9PiBzLnRvTG93ZXJDYXNlKCkpO1xuICByZXR1cm4gdmFsaWRTZXZlcml0aWVzLmluY2x1ZGVzKHNldmVyaXR5LnRvTG93ZXJDYXNlKCkpIHx8IHNldmVyaXR5ID09PSAnYWxsJztcbn1cblxuZnVuY3Rpb24gZmlsdGVyQnlTZXZlcml0eShcbiAgcmVwb3J0OiBBbmFseXNpc1JlcG9ydCxcbiAgbWluU2V2ZXJpdHk6IFNldmVyaXR5IHwgJ2FsbCdcbik6IEFuYWx5c2lzUmVwb3J0IHtcbiAgaWYgKG1pblNldmVyaXR5ID09PSAnYWxsJykge1xuICAgIHJldHVybiByZXBvcnQ7XG4gIH1cbiAgXG4gIGNvbnN0IHNldmVyaXR5T3JkZXI6IFJlY29yZDxTZXZlcml0eSwgbnVtYmVyPiA9IHtcbiAgICBbU2V2ZXJpdHkuQ3JpdGljYWxdOiAwLFxuICAgIFtTZXZlcml0eS5IaWdoXTogMSxcbiAgICBbU2V2ZXJpdHkuTWVkaXVtXTogMixcbiAgICBbU2V2ZXJpdHkuTG93XTogMyxcbiAgICBbU2V2ZXJpdHkuSW5mb106IDRcbiAgfTtcbiAgXG4gIGNvbnN0IG1pbkxldmVsID0gc2V2ZXJpdHlPcmRlclttaW5TZXZlcml0eSBhcyBTZXZlcml0eV07XG4gIFxuICBjb25zdCBmaWx0ZXJlZEZpbGVzID0gcmVwb3J0LmZpbGVzLm1hcChmaWxlID0+ICh7XG4gICAgLi4uZmlsZSxcbiAgICByZXN1bHRzOiBmaWxlLnJlc3VsdHMuZmlsdGVyKHIgPT4gc2V2ZXJpdHlPcmRlcltyLnNldmVyaXR5XSA8PSBtaW5MZXZlbClcbiAgfSkpO1xuICBcbiAgY29uc3QgdG90YWxJc3N1ZXMgPSBmaWx0ZXJlZEZpbGVzLnJlZHVjZSgoc3VtLCBmKSA9PiBzdW0gKyBmLnJlc3VsdHMubGVuZ3RoLCAwKTtcbiAgXG4gIHJldHVybiB7XG4gICAgLi4ucmVwb3J0LFxuICAgIGZpbGVzOiBmaWx0ZXJlZEZpbGVzLFxuICAgIHRvdGFsSXNzdWVzXG4gIH07XG59XG5cbmZ1bmN0aW9uIGNvbGxlY3RGaWxlcyh0YXJnZXQ6IHN0cmluZywgcmVjdXJzaXZlOiBib29sZWFuKTogc3RyaW5nW10ge1xuICBjb25zdCByZXNvbHZlZFBhdGggPSBwYXRoLnJlc29sdmUodGFyZ2V0KTtcbiAgXG4gIGlmICghZnMuZXhpc3RzU3luYyhyZXNvbHZlZFBhdGgpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBQYXRoIGRvZXMgbm90IGV4aXN0OiAke3Jlc29sdmVkUGF0aH1gKTtcbiAgfVxuICBcbiAgY29uc3Qgc3RhdHMgPSBmcy5zdGF0U3luYyhyZXNvbHZlZFBhdGgpO1xuICBcbiAgaWYgKHN0YXRzLmlzRmlsZSgpKSB7XG4gICAgaWYgKCFyZXNvbHZlZFBhdGguZW5kc1dpdGgoJy5zb2wnKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdGaWxlIG11c3QgaGF2ZSAuc29sIGV4dGVuc2lvbicpO1xuICAgIH1cbiAgICByZXR1cm4gW3Jlc29sdmVkUGF0aF07XG4gIH1cbiAgXG4gIGlmIChzdGF0cy5pc0RpcmVjdG9yeSgpKSB7XG4gICAgaWYgKHJlY3Vyc2l2ZSkge1xuICAgICAgcmV0dXJuIHJlYWREaXJlY3RvcnkocmVzb2x2ZWRQYXRoLCAnLnNvbCcpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMocmVzb2x2ZWRQYXRoKTtcbiAgICAgIHJldHVybiBlbnRyaWVzXG4gICAgICAgIC5maWx0ZXIoZSA9PiBlLmVuZHNXaXRoKCcuc29sJykpXG4gICAgICAgIC5tYXAoZSA9PiBwYXRoLmpvaW4ocmVzb2x2ZWRQYXRoLCBlKSk7XG4gICAgfVxuICB9XG4gIFxuICByZXR1cm4gW107XG59XG5cbmZ1bmN0aW9uIHJ1bkFuYWx5c2lzKHRhcmdldDogc3RyaW5nLCBvcHRpb25zOiBDbGlPcHRpb25zKTogdm9pZCB7XG4gIGNvbnN0IGZpbGVzID0gY29sbGVjdEZpbGVzKHRhcmdldCwgb3B0aW9ucy5yZWN1cnNpdmUpO1xuICBcbiAgaWYgKGZpbGVzLmxlbmd0aCA9PT0gMCkge1xuICAgIGNvbnNvbGUubG9nKCdcXHgxYlszM21ObyBTb2xpZGl0eSBmaWxlcyBmb3VuZCB0byBhbmFseXplLlxceDFiWzBtJyk7XG4gICAgcmV0dXJuO1xuICB9XG4gIFxuICBjb25zdCBhbmFseXplck9wdGlvbnM6IEFuYWx5emVyT3B0aW9ucyA9IHtcbiAgICBleGNsdWRlUGF0dGVybnM6IG9wdGlvbnMuZXhjbHVkZSBhcyBWdWxuZXJhYmlsaXR5VHlwZVtdLFxuICAgIGluY2x1ZGVXYXJuaW5nczogb3B0aW9ucy5zZXZlcml0eSA9PT0gJ2FsbCcgfHwgb3B0aW9ucy5zZXZlcml0eSA9PT0gJ2luZm8nXG4gIH07XG4gIFxuICBjb25zdCBhbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKGFuYWx5emVyT3B0aW9ucyk7XG4gIGxldCByZXBvcnQgPSBhbmFseXplci5hbmFseXplRmlsZXMoZmlsZXMpO1xuICBcbiAgaWYgKG9wdGlvbnMuc2V2ZXJpdHkgIT09ICdhbGwnKSB7XG4gICAgcmVwb3J0ID0gZmlsdGVyQnlTZXZlcml0eShyZXBvcnQsIG9wdGlvbnMuc2V2ZXJpdHkgYXMgU2V2ZXJpdHkpO1xuICB9XG4gIFxuICBsZXQgb3V0cHV0OiBzdHJpbmc7XG4gIFxuICBpZiAob3B0aW9ucy5qc29uKSB7XG4gICAgb3V0cHV0ID0gSlNPTi5zdHJpbmdpZnkocmVwb3J0LCBudWxsLCAyKTtcbiAgfSBlbHNlIHtcbiAgICBvdXRwdXQgPSBmb3JtYXRBbmFseXNpc1Jlc3VsdHMocmVwb3J0LmZpbGVzLmZsYXRNYXAoZiA9PiBmLnJlc3VsdHMpKTtcbiAgICBcbiAgICBpZiAoIW9wdGlvbnMucXVpZXQpIHtcbiAgICAgIGNvbnN0IHN1bW1hcnkgPSBnZW5lcmF0ZVN1bW1hcnkocmVwb3J0LmZpbGVzLmZsYXRNYXAoZiA9PiBmLnJlc3VsdHMpKTtcbiAgICAgIG91dHB1dCArPSBmb3JtYXRTdW1tYXJ5KHN1bW1hcnkpO1xuICAgIH1cbiAgfVxuICBcbiAgaWYgKG9wdGlvbnMub3V0cHV0KSB7XG4gICAgZnMud3JpdGVGaWxlU3luYyhwYXRoLnJlc29sdmUob3B0aW9ucy5vdXRwdXQpLCBvdXRwdXQpO1xuICAgIGNvbnNvbGUubG9nKGBcXHgxYlszMm1SZXN1bHRzIHdyaXR0ZW4gdG86ICR7b3B0aW9ucy5vdXRwdXR9XFx4MWJbMG1gKTtcbiAgfSBlbHNlIHtcbiAgICBjb25zb2xlLmxvZyhvdXRwdXQpO1xuICB9XG4gIFxuICBwcm9jZXNzLmV4aXQocmVwb3J0LnRvdGFsSXNzdWVzID4gMCA/IDEgOiAwKTtcbn1cblxuZnVuY3Rpb24gbWFpbigpOiB2b2lkIHtcbiAgY29uc3QgYXJncyA9IHByb2Nlc3MuYXJndi5zbGljZSgyKTtcbiAgY29uc3QgeyB0YXJnZXQsIG9wdGlvbnMgfSA9IHBhcnNlQXJncyhhcmdzKTtcbiAgXG4gIGlmIChvcHRpb25zLmhlbHApIHtcbiAgICBwcmludEhlbHAoKTtcbiAgICBwcm9jZXNzLmV4aXQoMCk7XG4gIH1cbiAgXG4gIGlmIChvcHRpb25zLnZlcnNpb24pIHtcbiAgICBjb25zb2xlLmxvZyhgc21hcnQtY29udHJhY3QtYXVkaXRvciB2JHtWRVJTSU9OfWApO1xuICAgIHByb2Nlc3MuZXhpdCgwKTtcbiAgfVxuICBcbiAgaWYgKCF0YXJnZXQpIHtcbiAgICBwcmludEJhbm5lcigpO1xuICAgIGNvbnNvbGUubG9nKCdcXHgxYlszMW1FcnJvcjogTm8gdGFyZ2V0IGZpbGUgb3IgZGlyZWN0b3J5IHNwZWNpZmllZC5cXHgxYlswbScpO1xuICAgIGNvbnNvbGUubG9nKCdVc2UgLS1oZWxwIGZvciB1c2FnZSBpbmZvcm1hdGlvbi4nKTtcbiAgICBwcm9jZXNzLmV4aXQoMSk7XG4gIH1cbiAgXG4gIGlmIChvcHRpb25zLmV4Y2x1ZGUubGVuZ3RoID4gMCkge1xuICAgIGNvbnN0IHZhbGlkVHlwZXMgPSBnZXRBbGxWdWxuZXJhYmlsaXR5VHlwZXMoKS5tYXAodCA9PiB0LnRvTG93ZXJDYXNlKCkpO1xuICAgIGZvciAoY29uc3QgZXhjbHVkZSBvZiBvcHRpb25zLmV4Y2x1ZGUpIHtcbiAgICAgIGlmICghdmFsaWRUeXBlcy5pbmNsdWRlcyhleGNsdWRlLnRvTG93ZXJDYXNlKCkpKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBcXHgxYlszM21XYXJuaW5nOiBVbmtub3duIHZ1bG5lcmFiaWxpdHkgdHlwZTogJHtleGNsdWRlfVxceDFiWzBtYCk7XG4gICAgICB9XG4gICAgfVxuICB9XG4gIFxuICBpZiAoIXZhbGlkYXRlU2V2ZXJpdHkob3B0aW9ucy5zZXZlcml0eSkpIHtcbiAgICBjb25zb2xlLmxvZyhgXFx4MWJbMzFtRXJyb3I6IEludmFsaWQgc2V2ZXJpdHkgbGV2ZWw6ICR7b3B0aW9ucy5zZXZlcml0eX1cXHgxYlswbWApO1xuICAgIGNvbnNvbGUubG9nKCdWYWxpZCBsZXZlbHM6IGNyaXRpY2FsLCBoaWdoLCBtZWRpdW0sIGxvdywgaW5mbywgYWxsJyk7XG4gICAgcHJvY2Vzcy5leGl0KDEpO1xuICB9XG4gIFxuICBpZiAoIW9wdGlvbnMucXVpZXQpIHtcbiAgICBwcmludEJhbm5lcigpO1xuICB9XG4gIFxuICB0cnkge1xuICAgIHJ1bkFuYWx5c2lzKHRhcmdldCwgb3B0aW9ucyk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc3QgbWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogJ1Vua25vd24gZXJyb3InO1xuICAgIGNvbnNvbGUubG9nKGBcXHgxYlszMW1FcnJvcjogJHttZXNzYWdlfVxceDFiWzBtYCk7XG4gICAgcHJvY2Vzcy5leGl0KDEpO1xuICB9XG59XG5cbmV4cG9ydCB7XG4gIFNtYXJ0Q29udHJhY3RBbmFseXplcixcbiAgY3JlYXRlQW5hbHl6ZXIsXG4gIGFuYWx5emVDb250cmFjdHMsXG4gIFZ1bG5lcmFiaWxpdHlUeXBlLFxuICBTZXZlcml0eSxcbiAgQW5hbHlzaXNSZXBvcnQsXG4gIEFuYWx5emVyT3B0aW9uc1xufTtcblxuaWYgKHJlcXVpcmUubWFpbiA9PT0gbW9kdWxlKSB7XG4gIG1haW4oKTtcbn1cbiJdfQ==