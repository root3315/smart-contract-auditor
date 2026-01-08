"use strict";
/**
 * Utility functions for smart contract analysis.
 * Provides file operations, string manipulation, and formatting helpers.
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
exports.readSolidityFile = readSolidityFile;
exports.readDirectory = readDirectory;
exports.extractLine = extractLine;
exports.getSurroundingLines = getSurroundingLines;
exports.formatSeverity = formatSeverity;
exports.formatAnalysisResults = formatAnalysisResults;
exports.truncateCode = truncateCode;
exports.generateSummary = generateSummary;
exports.formatSummary = formatSummary;
exports.escapeRegExp = escapeRegExp;
exports.normalizeWhitespace = normalizeWhitespace;
exports.isCommentLine = isCommentLine;
exports.filterComments = filterComments;
exports.getContractName = getContractName;
exports.getPragmaVersion = getPragmaVersion;
exports.extractFunctionBody = extractFunctionBody;
exports.hasModifier = hasModifier;
exports.findStateVariables = findStateVariables;
exports.findFunctions = findFunctions;
exports.isPayable = isPayable;
exports.hasConstructor = hasConstructor;
exports.findEvents = findEvents;
exports.findModifiers = findModifiers;
exports.countLines = countLines;
exports.getInheritanceChain = getInheritanceChain;
exports.isUpgradeable = isUpgradeable;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const patterns_1 = require("./patterns");
function readSolidityFile(filePath) {
    const absolutePath = path.resolve(filePath);
    const content = fs.readFileSync(absolutePath, 'utf-8');
    const lines = content.split(/\r?\n/);
    return { path: absolutePath, content, lines };
}
function readDirectory(dirPath, extension = '.sol') {
    const files = [];
    function traverse(currentPath) {
        const entries = fs.readdirSync(currentPath, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(currentPath, entry.name);
            if (entry.isDirectory()) {
                if (entry.name !== 'node_modules' && !entry.name.startsWith('.')) {
                    traverse(fullPath);
                }
            }
            else if (entry.isFile() && entry.name.endsWith(extension)) {
                files.push(fullPath);
            }
        }
    }
    traverse(path.resolve(dirPath));
    return files;
}
function extractLine(content, lineNumber) {
    const lines = content.split(/\r?\n/);
    const index = lineNumber - 1;
    if (index >= 0 && index < lines.length) {
        return lines[index].trim();
    }
    return '';
}
function getSurroundingLines(content, lineNumber, contextLines = 2) {
    const lines = content.split(/\r?\n/);
    const index = lineNumber - 1;
    const before = lines.slice(Math.max(0, index - contextLines), index);
    const target = lines[index] || '';
    const after = lines.slice(index + 1, index + 1 + contextLines);
    return { before, target, after };
}
function formatSeverity(severity) {
    const colors = {
        [patterns_1.Severity.Critical]: '\x1b[31m\x1b[1mCRITICAL\x1b[0m',
        [patterns_1.Severity.High]: '\x1b[31mHIGH\x1b[0m',
        [patterns_1.Severity.Medium]: '\x1b[33mMEDIUM\x1b[0m',
        [patterns_1.Severity.Low]: '\x1b[36mLOW\x1b[0m',
        [patterns_1.Severity.Info]: '\x1b[32mINFO\x1b[0m'
    };
    return colors[severity] || severity;
}
function formatAnalysisResults(results) {
    if (results.length === 0) {
        return '\n\x1b[32m✓ No vulnerabilities detected\x1b[0m\n';
    }
    const bySeverity = {
        [patterns_1.Severity.Critical]: [],
        [patterns_1.Severity.High]: [],
        [patterns_1.Severity.Medium]: [],
        [patterns_1.Severity.Low]: [],
        [patterns_1.Severity.Info]: []
    };
    for (const result of results) {
        bySeverity[result.severity].push(result);
    }
    let output = '\n';
    output += '═'.repeat(70) + '\n';
    output += 'SECURITY ANALYSIS RESULTS\n';
    output += '═'.repeat(70) + '\n\n';
    const severityOrder = [
        patterns_1.Severity.Critical,
        patterns_1.Severity.High,
        patterns_1.Severity.Medium,
        patterns_1.Severity.Low,
        patterns_1.Severity.Info
    ];
    for (const severity of severityOrder) {
        const issues = bySeverity[severity];
        if (issues.length === 0)
            continue;
        output += `\n${formatSeverity(severity)} (${issues.length} issue${issues.length > 1 ? 's' : ''})\n`;
        output += '─'.repeat(50) + '\n';
        for (const issue of issues) {
            const fileRef = issue.file ? `${path.basename(issue.file)}:` : '';
            output += `\n  [${fileRef}${issue.line}] ${issue.name}\n`;
            output += `    ${issue.description}\n`;
            output += `    Code: ${truncateCode(issue.code)}\n`;
            output += `    → ${issue.recommendation}\n`;
        }
    }
    output += '\n' + '═'.repeat(70) + '\n';
    output += `Total: ${results.length} vulnerability(ies) found\n`;
    output += '═'.repeat(70) + '\n';
    return output;
}
function truncateCode(code, maxLength = 60) {
    const trimmed = code.trim();
    if (trimmed.length <= maxLength) {
        return trimmed;
    }
    return trimmed.substring(0, maxLength - 3) + '...';
}
function generateSummary(results) {
    const bySeverity = {
        [patterns_1.Severity.Critical]: 0,
        [patterns_1.Severity.High]: 0,
        [patterns_1.Severity.Medium]: 0,
        [patterns_1.Severity.Low]: 0,
        [patterns_1.Severity.Info]: 0
    };
    const weights = {
        [patterns_1.Severity.Critical]: 10,
        [patterns_1.Severity.High]: 5,
        [patterns_1.Severity.Medium]: 3,
        [patterns_1.Severity.Low]: 1,
        [patterns_1.Severity.Info]: 0
    };
    for (const result of results) {
        bySeverity[result.severity]++;
    }
    let riskScore = 0;
    for (const severity of Object.keys(bySeverity)) {
        riskScore += bySeverity[severity] * weights[severity];
    }
    return {
        total: results.length,
        bySeverity,
        riskScore: Math.min(100, riskScore)
    };
}
function formatSummary(summary) {
    let output = '\n';
    output += '┌─────────────────────────────────────────┐\n';
    output += '│         ANALYSIS SUMMARY                │\n';
    output += '├─────────────────────────────────────────┤\n';
    output += `│ Total Issues: ${String(summary.total).padEnd(26)}│\n`;
    output += '├─────────────────────────────────────────┤\n';
    output += `│ Critical: ${String(summary.bySeverity[patterns_1.Severity.Critical]).padEnd(30)}│\n`;
    output += `│ High:     ${String(summary.bySeverity[patterns_1.Severity.High]).padEnd(30)}│\n`;
    output += `│ Medium:   ${String(summary.bySeverity[patterns_1.Severity.Medium]).padEnd(30)}│\n`;
    output += `│ Low:      ${String(summary.bySeverity[patterns_1.Severity.Low]).padEnd(30)}│\n`;
    output += `│ Info:     ${String(summary.bySeverity[patterns_1.Severity.Info]).padEnd(30)}│\n`;
    output += '├─────────────────────────────────────────┤\n';
    const riskLevel = getRiskLevel(summary.riskScore);
    const riskColor = getRiskColor(riskLevel);
    output += `│ Risk Score: ${riskColor}${String(summary.riskScore).padEnd(28)}\x1b[0m│\n`;
    output += `│ Risk Level: ${riskColor}${riskLevel.padEnd(28)}\x1b[0m│\n`;
    output += '└─────────────────────────────────────────┘\n';
    return output;
}
function getRiskLevel(score) {
    if (score >= 80)
        return 'CRITICAL';
    if (score >= 50)
        return 'HIGH';
    if (score >= 30)
        return 'MEDIUM';
    if (score >= 10)
        return 'LOW';
    return 'MINIMAL';
}
function getRiskColor(level) {
    switch (level) {
        case 'CRITICAL': return '\x1b[31m\x1b[1m';
        case 'HIGH': return '\x1b[31m';
        case 'MEDIUM': return '\x1b[33m';
        case 'LOW': return '\x1b[36m';
        default: return '\x1b[32m';
    }
}
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function normalizeWhitespace(code) {
    return code.replace(/\s+/g, ' ').trim();
}
function isCommentLine(line) {
    const trimmed = line.trim();
    return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}
function filterComments(lines) {
    return lines.filter(line => !isCommentLine(line));
}
function getContractName(content) {
    const match = content.match(/contract\s+(\w+)/i);
    return match ? match[1] : null;
}
function getPragmaVersion(content) {
    const match = content.match(/pragma\s+solidity\s+([^\s;]+)/i);
    return match ? match[1] : null;
}
function extractFunctionBody(content, functionName) {
    const functionPattern = new RegExp(`function\\s+${functionName}\\s*\\([^)]*\\)\\s*(?:[^{]*)\\{([^}]*)\\}`, 'is');
    const match = content.match(functionPattern);
    return match ? match[1] : null;
}
function hasModifier(content, functionName, modifier) {
    const functionPattern = new RegExp(`function\\s+${functionName}\\s*\\([^)]*\\)\\s*([^\\{]*)\\{`, 'i');
    const match = content.match(functionPattern);
    if (match && match[1]) {
        return new RegExp(modifier, 'i').test(match[1]);
    }
    return false;
}
function findStateVariables(content) {
    const stateVarPattern = /(?:uint|int|address|bool|string|bytes\d*|mapping[^;]+)\s+(\w+)\s*(?:;|=)/gi;
    const matches = [];
    let match;
    while ((match = stateVarPattern.exec(content)) !== null) {
        matches.push(match[1]);
    }
    return matches;
}
function findFunctions(content) {
    const lines = content.split(/\r?\n/);
    const functions = [];
    const functionPattern = /function\s+(\w+)\s*\([^)]*\)\s*(?:external|public|private|internal)?\s*([^{]*)/gi;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = functionPattern.exec(line);
        if (match) {
            const name = match[1];
            const modifiersStr = match[2] || '';
            const visibility = modifiersStr.match(/(external|public|private|internal)/i)?.[1] || 'internal';
            const modifiers = modifiersStr.match(/\b(\w+)\b/g)?.filter(m => !['external', 'public', 'private', 'internal', 'pure', 'view', 'payable'].includes(m.toLowerCase())) || [];
            functions.push({
                name,
                visibility,
                modifiers,
                line: i + 1
            });
        }
    }
    return functions;
}
function isPayable(content) {
    return /payable/i.test(content);
}
function hasConstructor(content) {
    return /constructor\s*\(/i.test(content);
}
function findEvents(content) {
    const eventPattern = /event\s+(\w+)\s*\([^)]*\)/gi;
    const events = [];
    let match;
    while ((match = eventPattern.exec(content)) !== null) {
        events.push(match[1]);
    }
    return events;
}
function findModifiers(content) {
    const modifierPattern = /modifier\s+(\w+)\s*\([^)]*\)/gi;
    const modifiers = [];
    let match;
    while ((match = modifierPattern.exec(content)) !== null) {
        modifiers.push(match[1]);
    }
    return modifiers;
}
function countLines(content) {
    const lines = content.split(/\r?\n/);
    let code = 0;
    let comments = 0;
    let blank = 0;
    let inMultiLineComment = false;
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed === '') {
            blank++;
            continue;
        }
        if (inMultiLineComment) {
            comments++;
            if (trimmed.includes('*/')) {
                inMultiLineComment = false;
            }
            continue;
        }
        if (trimmed.startsWith('/*')) {
            comments++;
            if (!trimmed.includes('*/')) {
                inMultiLineComment = true;
            }
            continue;
        }
        if (trimmed.startsWith('//')) {
            comments++;
            continue;
        }
        code++;
    }
    return { total: lines.length, code, comments, blank };
}
function getInheritanceChain(content) {
    const inheritPattern = /contract\s+\w+\s+is\s+([^{]+)/i;
    const match = content.match(inheritPattern);
    if (match && match[1]) {
        return match[1].split(',').map(c => c.trim());
    }
    return [];
}
function isUpgradeable(content) {
    const upgradeablePatterns = [
        /Initializable/i,
        /UUPSUpgradeable/i,
        /TransparentUpgradeableProxy/i,
        /proxy/i
    ];
    return upgradeablePatterns.some(pattern => pattern.test(content));
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdXRpbHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOzs7R0FHRzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFZSCw0Q0FLQztBQUVELHNDQXFCQztBQUVELGtDQU9DO0FBRUQsa0RBYUM7QUFFRCx3Q0FTQztBQUVELHNEQW1EQztBQUVELG9DQU1DO0FBRUQsMENBbUNDO0FBRUQsc0NBcUJDO0FBb0JELG9DQUVDO0FBRUQsa0RBRUM7QUFFRCxzQ0FHQztBQUVELHdDQUVDO0FBRUQsMENBR0M7QUFFRCw0Q0FHQztBQUVELGtEQU9DO0FBRUQsa0NBVUM7QUFFRCxnREFVQztBQUVELHNDQXNDQztBQUVELDhCQUVDO0FBRUQsd0NBRUM7QUFFRCxnQ0FVQztBQUVELHNDQVVDO0FBRUQsZ0NBd0NDO0FBRUQsa0RBU0M7QUFFRCxzQ0FTQztBQXhaRCx1Q0FBeUI7QUFDekIsMkNBQTZCO0FBQzdCLHlDQUFzRDtBQVF0RCxTQUFnQixnQkFBZ0IsQ0FBQyxRQUFnQjtJQUMvQyxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQzVDLE1BQU0sT0FBTyxHQUFHLEVBQUUsQ0FBQyxZQUFZLENBQUMsWUFBWSxFQUFFLE9BQU8sQ0FBQyxDQUFDO0lBQ3ZELE1BQU0sS0FBSyxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDckMsT0FBTyxFQUFFLElBQUksRUFBRSxZQUFZLEVBQUUsT0FBTyxFQUFFLEtBQUssRUFBRSxDQUFDO0FBQ2hELENBQUM7QUFFRCxTQUFnQixhQUFhLENBQUMsT0FBZSxFQUFFLFlBQW9CLE1BQU07SUFDdkUsTUFBTSxLQUFLLEdBQWEsRUFBRSxDQUFDO0lBRTNCLFNBQVMsUUFBUSxDQUFDLFdBQW1CO1FBQ25DLE1BQU0sT0FBTyxHQUFHLEVBQUUsQ0FBQyxXQUFXLENB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LGNBQWMsQ0FBQyxDQUFDO0lBRTVDLElBQUksS0FBSyxJQUFJLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDO1FBQ3RCLE9BQU8sS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUNoRCxDQUFDO0lBRUQsT0FBTyxFQUFFLENBQUM7QUFDWixDQUFDO0FBRUQsU0FBZ0IsYUFBYSxDQUFDLE9BQWU7SUFDM0MsTUFBTSxtQkFBbUIsR0FBRztRQUMxQixnQkFBZ0I7UUFDaEIsa0JBQWtCO1FBQ2xCLDhCQUE4QjtRQUM5QixRQUFRO0tBQ1QsQ0FBQztJQUVGLE9BQU8sbUJBQW1CLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDO0FBQ3BFLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFV0aWxpdHkgZnVuY3Rpb25zIGZvciBzbWFydCBjb250cmFjdCBhbmFseXNpcy5cbiAqIFByb3ZpZGVzIGZpbGUgb3BlcmF0aW9ucywgc3RyaW5nIG1hbmlwdWxhdGlvbiwgYW5kIGZvcm1hdHRpbmcgaGVscGVycy5cbiAqL1xuXG5pbXBvcnQgKiBhcyBmcyBmcm9tICdmcyc7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IHsgQW5hbHlzaXNSZXN1bHQsIFNldmVyaXR5IH0gZnJvbSAnLi9wYXR0ZXJucyc7XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmlsZUNvbnRlbnQge1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgbGluZXM6IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcmVhZFNvbGlkaXR5RmlsZShmaWxlUGF0aDogc3RyaW5nKTogRmlsZUNvbnRlbnQge1xuICBjb25zdCBhYnNvbHV0ZVBhdGggPSBwYXRoLnJlc29sdmUoZmlsZVBhdGgpO1xuICBjb25zdCBjb250ZW50ID0gZnMucmVhZEZpbGVTeW5jKGFic29sdXRlUGF0aCwgJ3V0Zi04Jyk7XG4gIGNvbnN0IGxpbmVzID0gY29udGVudC5zcGxpdCgvXFxyP1xcbi8pO1xuICByZXR1cm4geyBwYXRoOiBhYnNvbHV0ZVBhdGgsIGNvbnRlbnQsIGxpbmVzIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkRGlyZWN0b3J5KGRpclBhdGg6IHN0cmluZywgZXh0ZW5zaW9uOiBzdHJpbmcgPSAnLnNvbCcpOiBzdHJpbmdbXSB7XG4gIGNvbnN0IGZpbGVzOiBzdHJpbmdbXSA9IFtdO1xuXG4gIGZ1bmN0aW9uIHRyYXZlcnNlKGN1cnJlbnRQYXRoOiBzdHJpbmcpOiB2b2lkIHtcbiAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMoY3VycmVudFBhdGgsIHsgd2l0aEZpbGVUeXBlczogdHJ1ZSB9KTtcblxuICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgY29uc3QgZnVsbFBhdGggPSBwYXRoLmpvaW4oY3VycmVudFBhdGgsIGVudHJ5Lm5hbWUpO1xuXG4gICAgICBpZiAoZW50cnkuaXNEaXJlY3RvcnkoKSkge1xuICAgICAgICBpZiAoZW50cnkubmFtZSAhPT0gJ25vZGVfbW9kdWxlcycgJiYgIWVudHJ5Lm5hbWUuc3RhcnRzV2l0aCgnLicpKSB7XG4gICAgICAgICAgdHJhdmVyc2UoZnVsbFBhdGgpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2UgaWYgKGVudHJ5LmlzRmlsZSgpICYmIGVudHJ5Lm5hbWUuZW5kc1dpdGgoZXh0ZW5zaW9uKSkge1xuICAgICAgICBmaWxlcy5wdXNoKGZ1bGxQYXRoKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICB0cmF2ZXJzZShwYXRoLnJlc29sdmUoZGlyUGF0aCkpO1xuICByZXR1cm4gZmlsZXM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBleHRyYWN0TGluZShjb250ZW50OiBzdHJpbmcsIGxpbmVOdW1iZXI6IG51bWJlcik6IHN0cmluZyB7XG4gIGNvbnN0IGxpbmVzID0gY29udGVudC5zcGxpdCgvXFxyP1xcbi8pO1xuICBjb25zdCBpbmRleCA9IGxpbmVOdW1iZXIgLSAxO1xuICBpZiAoaW5kZXggPj0gMCAmJiBpbmRleCA8IGxpbmVzLmxlbmd0aCkge1xuICAgIHJldHVybiBsaW5lc1tpbmRleF0udHJpbSgpO1xuICB9XG4gIHJldHVybiAnJztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFN1cnJvdW5kaW5nTGluZXMoXG4gIGNvbnRlbnQ6IHN0cmluZyxcbiAgbGluZU51bWJlcjogbnVtYmVyLFxuICBjb250ZXh0TGluZXM6IG51bWJlciA9IDJcbik6IHsgYmVmb3JlOiBzdHJpbmdbXTsgdGFyZ2V0OiBzdHJpbmc7IGFmdGVyOiBzdHJpbmdbXSB9IHtcbiAgY29uc3QgbGluZXMgPSBjb250ZW50LnNwbGl0KC9cXHI/XFxuLyk7XG4gIGNvbnN0IGluZGV4ID0gbGluZU51bWJlciAtIDE7XG5cbiAgY29uc3QgYmVmb3JlID0gbGluZXMuc2xpY2UoTWF0aC5tYXgoMCwgaW5kZXggLSBjb250ZXh0TGluZXMpLCBpbmRleCk7XG4gIGNvbnN0IHRhcmdldCA9IGxpbmVzW2luZGV4XSB8fCAnJztcbiAgY29uc3QgYWZ0ZXIgPSBsaW5lcy5zbGljZShpbmRleCArIDEsIGluZGV4ICsgMSArIGNvbnRleHRMaW5lcyk7XG5cbiAgcmV0dXJuIHsgYmVmb3JlLCB0YXJnZXQsIGFmdGVyIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBmb3JtYXRTZXZlcml0eShzZXZlcml0eTogU2V2ZXJpdHkpOiBzdHJpbmcge1xuICBjb25zdCBjb2xvcnM6IFJlY29yZDxTZXZlcml0eSwgc3RyaW5nPiA9IHtcbiAgICBbU2V2ZXJpdHkuQ3JpdGljYWxdOiAnXFx4MWJbMzFtXFx4MWJbMW1DUklUSUNBTFxceDFiWzBtJyxcbiAgICBbU2V2ZXJpdHkuSGlnaF06ICdcXHgxYlszMW1ISUdIXFx4MWJbMG0nLFxuICAgIFtTZXZlcml0eS5NZWRpdW1dOiAnXFx4MWJbMzNtTUVESVVNXFx4MWJbMG0nLFxuICAgIFtTZXZlcml0eS5Mb3ddOiAnXFx4MWJbMzZtTE9XXFx4MWJbMG0nLFxuICAgIFtTZXZlcml0eS5JbmZvXTogJ1xceDFiWzMybUlORk9cXHgxYlswbSdcbiAgfTtcbiAgcmV0dXJuIGNvbG9yc1tzZXZlcml0eV0gfHwgc2V2ZXJpdHk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBmb3JtYXRBbmFseXNpc1Jlc3VsdHMocmVzdWx0czogQW5hbHlzaXNSZXN1bHRbXSk6IHN0cmluZyB7XG4gIGlmIChyZXN1bHRzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybiAnXFxuXFx4MWJbMzJt4pyTIE5vIHZ1bG5lcmFiaWxpdGllcyBkZXRlY3RlZFxceDFiWzBtXFxuJztcbiAgfVxuXG4gIGNvbnN0IGJ5U2V2ZXJpdHk6IFJlY29yZDxTZXZlcml0eSwgQW5hbHlzaXNSZXN1bHRbXT4gPSB7XG4gICAgW1NldmVyaXR5LkNyaXRpY2FsXTogW10sXG4gICAgW1NldmVyaXR5LkhpZ2hdOiBbXSxcbiAgICBbU2V2ZXJpdHkuTWVkaXVtXTogW10sXG4gICAgW1NldmVyaXR5Lkxvd106IFtdLFxuICAgIFtTZXZlcml0eS5JbmZvXTogW11cbiAgfTtcblxuICBmb3IgKGNvbnN0IHJlc3VsdCBvZiByZXN1bHRzKSB7XG4gICAgYnlTZXZlcml0eVtyZXN1bHQuc2V2ZXJpdHldLnB1c2gocmVzdWx0KTtcbiAgfVxuXG4gIGxldCBvdXRwdXQgPSAnXFxuJztcbiAgb3V0cHV0ICs9ICfilZAnLnJlcGVhdCg3MCkgKyAnXFxuJztcbiAgb3V0cHV0ICs9ICdTRUNVUklUWSBBTkFMWVNJUyBSRVNVTFRTXFxuJztcbiAgb3V0cHV0ICs9ICfilZAnLnJlcGVhdCg3MCkgKyAnXFxuXFxuJztcblxuICBjb25zdCBzZXZlcml0eU9yZGVyOiBTZXZlcml0eVtdID0gW1xuICAgIFNldmVyaXR5LkNyaXRpY2FsLFxuICAgIFNldmVyaXR5LkhpZ2gsXG4gICAgU2V2ZXJpdHkuTWVkaXVtLFxuICAgIFNldmVyaXR5LkxvdyxcbiAgICBTZXZlcml0eS5JbmZvXG4gIF07XG5cbiAgZm9yIChjb25zdCBzZXZlcml0eSBvZiBzZXZlcml0eU9yZGVyKSB7XG4gICAgY29uc3QgaXNzdWVzID0gYnlTZXZlcml0eVtzZXZlcml0eV07XG4gICAgaWYgKGlzc3Vlcy5sZW5ndGggPT09IDApIGNvbnRpbnVlO1xuXG4gICAgb3V0cHV0ICs9IGBcXG4ke2Zvcm1hdFNldmVyaXR5KHNldmVyaXR5KX0gKCR7aXNzdWVzLmxlbmd0aH0gaXNzdWUke2lzc3Vlcy5sZW5ndGggPiAxID8gJ3MnIDogJyd9KVxcbmA7XG4gICAgb3V0cHV0ICs9ICfilIAnLnJlcGVhdCg1MCkgKyAnXFxuJztcblxuICAgIGZvciAoY29uc3QgaXNzdWUgb2YgaXNzdWVzKSB7XG4gICAgICBjb25zdCBmaWxlUmVmID0gaXNzdWUuZmlsZSA/IGAke3BhdGguYmFzZW5hbWUoaXNzdWUuZmlsZSl9OmAgOiAnJztcbiAgICAgIG91dHB1dCArPSBgXFxuICBbJHtmaWxlUmVmfSR7aXNzdWUubGluZX1dICR7aXNzdWUubmFtZX1cXG5gO1xuICAgICAgb3V0cHV0ICs9IGAgICAgJHtpc3N1ZS5kZXNjcmlwdGlvbn1cXG5gO1xuICAgICAgb3V0cHV0ICs9IGAgICAgQ29kZTogJHt0cnVuY2F0ZUNvZGUoaXNzdWUuY29kZSl9XFxuYDtcbiAgICAgIG91dHB1dCArPSBgICAgIOKGkiAke2lzc3VlLnJlY29tbWVuZGF0aW9ufVxcbmA7XG4gICAgfVxuICB9XG5cbiAgb3V0cHV0ICs9ICdcXG4nICsgJ+KVkCcucmVwZWF0KDcwKSArICdcXG4nO1xuICBvdXRwdXQgKz0gYFRvdGFsOiAke3Jlc3VsdHMubGVuZ3RofSB2dWxuZXJhYmlsaXR5KGllcykgZm91bmRcXG5gO1xuICBvdXRwdXQgKz0gJ+KVkCcucmVwZWF0KDcwKSArICdcXG4nO1xuXG4gIHJldHVybiBvdXRwdXQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0cnVuY2F0ZUNvZGUoY29kZTogc3RyaW5nLCBtYXhMZW5ndGg6IG51bWJlciA9IDYwKTogc3RyaW5nIHtcbiAgY29uc3QgdHJpbW1lZCA9IGNvZGUudHJpbSgpO1xuICBpZiAodHJpbW1lZC5sZW5ndGggPD0gbWF4TGVuZ3RoKSB7XG4gICAgcmV0dXJuIHRyaW1tZWQ7XG4gIH1cbiAgcmV0dXJuIHRyaW1tZWQuc3Vic3RyaW5nKDAsIG1heExlbmd0aCAtIDMpICsgJy4uLic7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZW5lcmF0ZVN1bW1hcnkocmVzdWx0czogQW5hbHlzaXNSZXN1bHRbXSk6IHtcbiAgdG90YWw6IG51bWJlcjtcbiAgYnlTZXZlcml0eTogUmVjb3JkPFNldmVyaXR5LCBudW1iZXI+O1xuICByaXNrU2NvcmU6IG51bWJlcjtcbn0ge1xuICBjb25zdCBieVNldmVyaXR5OiBSZWNvcmQ8U2V2ZXJpdHksIG51bWJlcj4gPSB7XG4gICAgW1NldmVyaXR5LkNyaXRpY2FsXTogMCxcbiAgICBbU2V2ZXJpdHkuSGlnaF06IDAsXG4gICAgW1NldmVyaXR5Lk1lZGl1bV06IDAsXG4gICAgW1NldmVyaXR5Lkxvd106IDAsXG4gICAgW1NldmVyaXR5LkluZm9dOiAwXG4gIH07XG5cbiAgY29uc3Qgd2VpZ2h0czogUmVjb3JkPFNldmVyaXR5LCBudW1iZXI+ID0ge1xuICAgIFtTZXZlcml0eS5Dcml0aWNhbF06IDEwLFxuICAgIFtTZXZlcml0eS5IaWdoXTogNSxcbiAgICBbU2V2ZXJpdHkuTWVkaXVtXTogMyxcbiAgICBbU2V2ZXJpdHkuTG93XTogMSxcbiAgICBbU2V2ZXJpdHkuSW5mb106IDBcbiAgfTtcblxuICBmb3IgKGNvbnN0IHJlc3VsdCBvZiByZXN1bHRzKSB7XG4gICAgYnlTZXZlcml0eVtyZXN1bHQuc2V2ZXJpdHldKys7XG4gIH1cblxuICBsZXQgcmlza1Njb3JlID0gMDtcbiAgZm9yIChjb25zdCBzZXZlcml0eSBvZiBPYmplY3Qua2V5cyhieVNldmVyaXR5KSBhcyBTZXZlcml0eVtdKSB7XG4gICAgcmlza1Njb3JlICs9IGJ5U2V2ZXJpdHlbc2V2ZXJpdHldICogd2VpZ2h0c1tzZXZlcml0eV07XG4gIH1cblxuICByZXR1cm4ge1xuICAgIHRvdGFsOiByZXN1bHRzLmxlbmd0aCxcbiAgICBieVNldmVyaXR5LFxuICAgIHJpc2tTY29yZTogTWF0aC5taW4oMTAwLCByaXNrU2NvcmUpXG4gIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBmb3JtYXRTdW1tYXJ5KHN1bW1hcnk6IFJldHVyblR5cGU8dHlwZW9mIGdlbmVyYXRlU3VtbWFyeT4pOiBzdHJpbmcge1xuICBsZXQgb3V0cHV0ID0gJ1xcbic7XG4gIG91dHB1dCArPSAn4pSM4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSQXFxuJztcbiAgb3V0cHV0ICs9ICfilIIgICAgICAgICBBTkFMWVNJUyBTVU1NQVJZICAgICAgICAgICAgICAgIOKUglxcbic7XG4gIG91dHB1dCArPSAn4pSc4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSkXFxuJztcbiAgb3V0cHV0ICs9IGDilIIgVG90YWwgSXNzdWVzOiAke1N0cmluZyhzdW1tYXJ5LnRvdGFsKS5wYWRFbmQoMjYpfeKUglxcbmA7XG4gIG91dHB1dCArPSAn4pSc4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSkXFxuJztcbiAgb3V0cHV0ICs9IGDilIIgQ3JpdGljYWw6ICR7U3RyaW5nKHN1bW1hcnkuYnlTZXZlcml0eVtTZXZlcml0eS5Dcml0aWNhbF0pLnBhZEVuZCgzMCl94pSCXFxuYDtcbiAgb3V0cHV0ICs9IGDilIIgSGlnaDogICAgICR7U3RyaW5nKHN1bW1hcnkuYnlTZXZlcml0eVtTZXZlcml0eS5IaWdoXSkucGFkRW5kKDMwKX3ilIJcXG5gO1xuICBvdXRwdXQgKz0gYOKUgiBNZWRpdW06ICAgJHtTdHJpbmcoc3VtbWFyeS5ieVNldmVyaXR5W1NldmVyaXR5Lk1lZGl1bV0pLnBhZEVuZCgzMCl94pSCXFxuYDtcbiAgb3V0cHV0ICs9IGDilIIgTG93OiAgICAgICR7U3RyaW5nKHN1bW1hcnkuYnlTZXZlcml0eVtTZXZlcml0eS5Mb3ddKS5wYWRFbmQoMzApfeKUglxcbmA7XG4gIG91dHB1dCArPSBg4pSCIEluZm86ICAgICAke1N0cmluZyhzdW1tYXJ5LmJ5U2V2ZXJpdHlbU2V2ZXJpdHkuSW5mb10pLnBhZEVuZCgzMCl94pSCXFxuYDtcbiAgb3V0cHV0ICs9ICfilJzilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilKRcXG4nO1xuXG4gIGNvbnN0IHJpc2tMZXZlbCA9IGdldFJpc2tMZXZlbChzdW1tYXJ5LnJpc2tTY29yZSk7XG4gIGNvbnN0IHJpc2tDb2xvciA9IGdldFJpc2tDb2xvcihyaXNrTGV2ZWwpO1xuICBvdXRwdXQgKz0gYOKUgiBSaXNrIFNjb3JlOiAke3Jpc2tDb2xvcn0ke1N0cmluZyhzdW1tYXJ5LnJpc2tTY29yZSkucGFkRW5kKDI4KX1cXHgxYlswbeKUglxcbmA7XG4gIG91dHB1dCArPSBg4pSCIFJpc2sgTGV2ZWw6ICR7cmlza0NvbG9yfSR7cmlza0xldmVsLnBhZEVuZCgyOCl9XFx4MWJbMG3ilIJcXG5gO1xuICBvdXRwdXQgKz0gJ+KUlOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUmFxcbic7XG5cbiAgcmV0dXJuIG91dHB1dDtcbn1cblxuZnVuY3Rpb24gZ2V0Umlza0xldmVsKHNjb3JlOiBudW1iZXIpOiBzdHJpbmcge1xuICBpZiAoc2NvcmUgPj0gODApIHJldHVybiAnQ1JJVElDQUwnO1xuICBpZiAoc2NvcmUgPj0gNTApIHJldHVybiAnSElHSCc7XG4gIGlmIChzY29yZSA+PSAzMCkgcmV0dXJuICdNRURJVU0nO1xuICBpZiAoc2NvcmUgPj0gMTApIHJldHVybiAnTE9XJztcbiAgcmV0dXJuICdNSU5JTUFMJztcbn1cblxuZnVuY3Rpb24gZ2V0Umlza0NvbG9yKGxldmVsOiBzdHJpbmcpOiBzdHJpbmcge1xuICBzd2l0Y2ggKGxldmVsKSB7XG4gICAgY2FzZSAnQ1JJVElDQUwnOiByZXR1cm4gJ1xceDFiWzMxbVxceDFiWzFtJztcbiAgICBjYXNlICdISUdIJzogcmV0dXJuICdcXHgxYlszMW0nO1xuICAgIGNhc2UgJ01FRElVTSc6IHJldHVybiAnXFx4MWJbMzNtJztcbiAgICBjYXNlICdMT1cnOiByZXR1cm4gJ1xceDFiWzM2bSc7XG4gICAgZGVmYXVsdDogcmV0dXJuICdcXHgxYlszMm0nO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBlc2NhcGVSZWdFeHAoc3RyaW5nOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gc3RyaW5nLnJlcGxhY2UoL1suKis/XiR7fSgpfFtcXF1cXFxcXS9nLCAnXFxcXCQmJyk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVXaGl0ZXNwYWNlKGNvZGU6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBjb2RlLnJlcGxhY2UoL1xccysvZywgJyAnKS50cmltKCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpc0NvbW1lbnRMaW5lKGxpbmU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBjb25zdCB0cmltbWVkID0gbGluZS50cmltKCk7XG4gIHJldHVybiB0cmltbWVkLnN0YXJ0c1dpdGgoJy8vJykgfHwgdHJpbW1lZC5zdGFydHNXaXRoKCcvKicpIHx8IHRyaW1tZWQuc3RhcnRzV2l0aCgnKicpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZmlsdGVyQ29tbWVudHMobGluZXM6IHN0cmluZ1tdKTogc3RyaW5nW10ge1xuICByZXR1cm4gbGluZXMuZmlsdGVyKGxpbmUgPT4gIWlzQ29tbWVudExpbmUobGluZSkpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0Q29udHJhY3ROYW1lKGNvbnRlbnQ6IHN0cmluZyk6IHN0cmluZyB8IG51bGwge1xuICBjb25zdCBtYXRjaCA9IGNvbnRlbnQubWF0Y2goL2NvbnRyYWN0XFxzKyhcXHcrKS9pKTtcbiAgcmV0dXJuIG1hdGNoID8gbWF0Y2hbMV0gOiBudWxsO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0UHJhZ21hVmVyc2lvbihjb250ZW50OiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcbiAgY29uc3QgbWF0Y2ggPSBjb250ZW50Lm1hdGNoKC9wcmFnbWFcXHMrc29saWRpdHlcXHMrKFteXFxzO10rKS9pKTtcbiAgcmV0dXJuIG1hdGNoID8gbWF0Y2hbMV0gOiBudWxsO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZXh0cmFjdEZ1bmN0aW9uQm9keShjb250ZW50OiBzdHJpbmcsIGZ1bmN0aW9uTmFtZTogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCB7XG4gIGNvbnN0IGZ1bmN0aW9uUGF0dGVybiA9IG5ldyBSZWdFeHAoXG4gICAgYGZ1bmN0aW9uXFxcXHMrJHtmdW5jdGlvbk5hbWV9XFxcXHMqXFxcXChbXildKlxcXFwpXFxcXHMqKD86W157XSopXFxcXHsoW159XSopXFxcXH1gLFxuICAgICdpcydcbiAgKTtcbiAgY29uc3QgbWF0Y2ggPSBjb250ZW50Lm1hdGNoKGZ1bmN0aW9uUGF0dGVybik7XG4gIHJldHVybiBtYXRjaCA/IG1hdGNoWzFdIDogbnVsbDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGhhc01vZGlmaWVyKGNvbnRlbnQ6IHN0cmluZywgZnVuY3Rpb25OYW1lOiBzdHJpbmcsIG1vZGlmaWVyOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgZnVuY3Rpb25QYXR0ZXJuID0gbmV3IFJlZ0V4cChcbiAgICBgZnVuY3Rpb25cXFxccyske2Z1bmN0aW9uTmFtZX1cXFxccypcXFxcKFteKV0qXFxcXClcXFxccyooW15cXFxce10qKVxcXFx7YCxcbiAgICAnaSdcbiAgKTtcbiAgY29uc3QgbWF0Y2ggPSBjb250ZW50Lm1hdGNoKGZ1bmN0aW9uUGF0dGVybik7XG4gIGlmIChtYXRjaCAmJiBtYXRjaFsxXSkge1xuICAgIHJldHVybiBuZXcgUmVnRXhwKG1vZGlmaWVyLCAnaScpLnRlc3QobWF0Y2hbMV0pO1xuICB9XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZpbmRTdGF0ZVZhcmlhYmxlcyhjb250ZW50OiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gIGNvbnN0IHN0YXRlVmFyUGF0dGVybiA9IC8oPzp1aW50fGludHxhZGRyZXNzfGJvb2x8c3RyaW5nfGJ5dGVzXFxkKnxtYXBwaW5nW147XSspXFxzKyhcXHcrKVxccyooPzo7fD0pL2dpO1xuICBjb25zdCBtYXRjaGVzOiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbWF0Y2g6IFJlZ0V4cEV4ZWNBcnJheSB8IG51bGw7XG5cbiAgd2hpbGUgKChtYXRjaCA9IHN0YXRlVmFyUGF0dGVybi5leGVjKGNvbnRlbnQpKSAhPT0gbnVsbCkge1xuICAgIG1hdGNoZXMucHVzaChtYXRjaFsxXSk7XG4gIH1cblxuICByZXR1cm4gbWF0Y2hlcztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZpbmRGdW5jdGlvbnMoY29udGVudDogc3RyaW5nKTogQXJyYXk8e1xuICBuYW1lOiBzdHJpbmc7XG4gIHZpc2liaWxpdHk6IHN0cmluZztcbiAgbW9kaWZpZXJzOiBzdHJpbmdbXTtcbiAgbGluZTogbnVtYmVyO1xufT4ge1xuICBjb25zdCBsaW5lcyA9IGNvbnRlbnQuc3BsaXQoL1xccj9cXG4vKTtcbiAgY29uc3QgZnVuY3Rpb25zOiBBcnJheTx7XG4gICAgbmFtZTogc3RyaW5nO1xuICAgIHZpc2liaWxpdHk6IHN0cmluZztcbiAgICBtb2RpZmllcnM6IHN0cmluZ1tdO1xuICAgIGxpbmU6IG51bWJlcjtcbiAgfT4gPSBbXTtcblxuICBjb25zdCBmdW5jdGlvblBhdHRlcm4gPSAvZnVuY3Rpb25cXHMrKFxcdyspXFxzKlxcKFteKV0qXFwpXFxzKig/OmV4dGVybmFsfHB1YmxpY3xwcml2YXRlfGludGVybmFsKT9cXHMqKFtee10qKS9naTtcblxuICBmb3IgKGxldCBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuICAgIGNvbnN0IG1hdGNoID0gZnVuY3Rpb25QYXR0ZXJuLmV4ZWMobGluZSk7XG5cbiAgICBpZiAobWF0Y2gpIHtcbiAgICAgIGNvbnN0IG5hbWUgPSBtYXRjaFsxXTtcbiAgICAgIGNvbnN0IG1vZGlmaWVyc1N0ciA9IG1hdGNoWzJdIHx8ICcnO1xuICAgICAgY29uc3QgdmlzaWJpbGl0eSA9IG1vZGlmaWVyc1N0ci5tYXRjaCgvKGV4dGVybmFsfHB1YmxpY3xwcml2YXRlfGludGVybmFsKS9pKT8uWzFdIHx8ICdpbnRlcm5hbCc7XG4gICAgICBjb25zdCBtb2RpZmllcnMgPSBtb2RpZmllcnNTdHIubWF0Y2goL1xcYihcXHcrKVxcYi9nKT8uZmlsdGVyKG0gPT4gXG4gICAgICAgICFbJ2V4dGVybmFsJywgJ3B1YmxpYycsICdwcml2YXRlJywgJ2ludGVybmFsJywgJ3B1cmUnLCAndmlldycsICdwYXlhYmxlJ10uaW5jbHVkZXMobS50b0xvd2VyQ2FzZSgpKVxuICAgICAgKSB8fCBbXTtcblxuICAgICAgZnVuY3Rpb25zLnB1c2goe1xuICAgICAgICBuYW1lLFxuICAgICAgICB2aXNpYmlsaXR5LFxuICAgICAgICBtb2RpZmllcnMsXG4gICAgICAgIGxpbmU6IGkgKyAxXG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZnVuY3Rpb25zO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaXNQYXlhYmxlKGNvbnRlbnQ6IHN0cmluZyk6IGJvb2xlYW4ge1xuICByZXR1cm4gL3BheWFibGUvaS50ZXN0KGNvbnRlbnQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaGFzQ29uc3RydWN0b3IoY29udGVudDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIHJldHVybiAvY29uc3RydWN0b3JcXHMqXFwoL2kudGVzdChjb250ZW50KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZpbmRFdmVudHMoY29udGVudDogc3RyaW5nKTogc3RyaW5nW10ge1xuICBjb25zdCBldmVudFBhdHRlcm4gPSAvZXZlbnRcXHMrKFxcdyspXFxzKlxcKFteKV0qXFwpL2dpO1xuICBjb25zdCBldmVudHM6IHN0cmluZ1tdID0gW107XG4gIGxldCBtYXRjaDogUmVnRXhwRXhlY0FycmF5IHwgbnVsbDtcblxuICB3aGlsZSAoKG1hdGNoID0gZXZlbnRQYXR0ZXJuLmV4ZWMoY29udGVudCkpICE9PSBudWxsKSB7XG4gICAgZXZlbnRzLnB1c2gobWF0Y2hbMV0pO1xuICB9XG5cbiAgcmV0dXJuIGV2ZW50cztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZpbmRNb2RpZmllcnMoY29udGVudDogc3RyaW5nKTogc3RyaW5nW10ge1xuICBjb25zdCBtb2RpZmllclBhdHRlcm4gPSAvbW9kaWZpZXJcXHMrKFxcdyspXFxzKlxcKFteKV0qXFwpL2dpO1xuICBjb25zdCBtb2RpZmllcnM6IHN0cmluZ1tdID0gW107XG4gIGxldCBtYXRjaDogUmVnRXhwRXhlY0FycmF5IHwgbnVsbDtcblxuICB3aGlsZSAoKG1hdGNoID0gbW9kaWZpZXJQYXR0ZXJuLmV4ZWMoY29udGVudCkpICE9PSBudWxsKSB7XG4gICAgbW9kaWZpZXJzLnB1c2gobWF0Y2hbMV0pO1xuICB9XG5cbiAgcmV0dXJuIG1vZGlmaWVycztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGNvdW50TGluZXMoY29udGVudDogc3RyaW5nKTogeyB0b3RhbDogbnVtYmVyOyBjb2RlOiBudW1iZXI7IGNvbW1lbnRzOiBudW1iZXI7IGJsYW5rOiBudW1iZXIgfSB7XG4gIGNvbnN0IGxpbmVzID0gY29udGVudC5zcGxpdCgvXFxyP1xcbi8pO1xuICBsZXQgY29kZSA9IDA7XG4gIGxldCBjb21tZW50cyA9IDA7XG4gIGxldCBibGFuayA9IDA7XG4gIGxldCBpbk11bHRpTGluZUNvbW1lbnQgPSBmYWxzZTtcblxuICBmb3IgKGNvbnN0IGxpbmUgb2YgbGluZXMpIHtcbiAgICBjb25zdCB0cmltbWVkID0gbGluZS50cmltKCk7XG5cbiAgICBpZiAodHJpbW1lZCA9PT0gJycpIHtcbiAgICAgIGJsYW5rKys7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICBpZiAoaW5NdWx0aUxpbmVDb21tZW50KSB7XG4gICAgICBjb21tZW50cysrO1xuICAgICAgaWYgKHRyaW1tZWQuaW5jbHVkZXMoJyovJykpIHtcbiAgICAgICAgaW5NdWx0aUxpbmVDb21tZW50ID0gZmFsc2U7XG4gICAgICB9XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICBpZiAodHJpbW1lZC5zdGFydHNXaXRoKCcvKicpKSB7XG4gICAgICBjb21tZW50cysrO1xuICAgICAgaWYgKCF0cmltbWVkLmluY2x1ZGVzKCcqLycpKSB7XG4gICAgICAgIGluTXVsdGlMaW5lQ29tbWVudCA9IHRydWU7XG4gICAgICB9XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICBpZiAodHJpbW1lZC5zdGFydHNXaXRoKCcvLycpKSB7XG4gICAgICBjb21tZW50cysrO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgY29kZSsrO1xuICB9XG5cbiAgcmV0dXJuIHsgdG90YWw6IGxpbmVzLmxlbmd0aCwgY29kZSwgY29tbWVudHMsIGJsYW5rIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRJbmhlcml0YW5jZUNoYWluKGNvbnRlbnQ6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgY29uc3QgaW5oZXJpdFBhdHRlcm4gPSAvY29udHJhY3RcXHMrXFx3K1xccytpc1xccysoW157XSspL2k7XG4gIGNvbnN0IG1hdGNoID0gY29udGVudC5tYXRjaChpbmhlcml0UGF0dGVybik7XG5cbiAgaWYgKG1hdGNoICYmIG1hdGNoWzFdKSB7XG4gICAgcmV0dXJuIG1hdGNoWzFdLnNwbGl0KCcsJykubWFwKGMgPT4gYy50cmltKCkpO1xuICB9XG5cbiAgcmV0dXJuIFtdO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaXNVcGdyYWRlYWJsZShjb250ZW50OiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgdXBncmFkZWFibGVQYXR0ZXJucyA9IFtcbiAgICAvSW5pdGlhbGl6YWJsZS9pLFxuICAgIC9VVVBTVXBncmFkZWFibGUvaSxcbiAgICAvVHJhbnNwYXJlbnRVcGdyYWRlYWJsZVByb3h5L2ksXG4gICAgL3Byb3h5L2lcbiAgXTtcblxuICByZXR1cm4gdXBncmFkZWFibGVQYXR0ZXJucy5zb21lKHBhdHRlcm4gPT4gcGF0dGVybi50ZXN0KGNvbnRlbnQpKTtcbn1cbiJdfQ==