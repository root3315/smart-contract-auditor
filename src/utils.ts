/**
 * Utility functions for smart contract analysis.
 * Provides file operations, string manipulation, and formatting helpers.
 */

import * as fs from 'fs';
import * as path from 'path';
import { AnalysisResult, Severity } from './patterns';

export interface FileContent {
  path: string;
  content: string;
  lines: string[];
}

export function readSolidityFile(filePath: string): FileContent {
  const absolutePath = path.resolve(filePath);
  const content = fs.readFileSync(absolutePath, 'utf-8');
  const lines = content.split(/\r?\n/);
  return { path: absolutePath, content, lines };
}

export function readDirectory(dirPath: string, extension: string = '.sol'): string[] {
  const files: string[] = [];
  
  function traverse(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && !entry.name.startsWith('.')) {
          traverse(fullPath);
        }
      } else if (entry.isFile() && entry.name.endsWith(extension)) {
        files.push(fullPath);
      }
    }
  }
  
  traverse(path.resolve(dirPath));
  return files;
}

export function extractLine(content: string, lineNumber: number): string {
  const lines = content.split(/\r?\n/);
  const index = lineNumber - 1;
  if (index >= 0 && index < lines.length) {
    return lines[index].trim();
  }
  return '';
}

export function getSurroundingLines(
  content: string,
  lineNumber: number,
  contextLines: number = 2
): { before: string[]; target: string; after: string[] } {
  const lines = content.split(/\r?\n/);
  const index = lineNumber - 1;
  
  const before = lines.slice(Math.max(0, index - contextLines), index);
  const target = lines[index] || '';
  const after = lines.slice(index + 1, index + 1 + contextLines);
  
  return { before, target, after };
}

export function formatSeverity(severity: Severity): string {
  const colors: Record<Severity, string> = {
    [Severity.Critical]: '\x1b[31m\x1b[1mCRITICAL\x1b[0m',
    [Severity.High]: '\x1b[31mHIGH\x1b[0m',
    [Severity.Medium]: '\x1b[33mMEDIUM\x1b[0m',
    [Severity.Low]: '\x1b[36mLOW\x1b[0m',
    [Severity.Info]: '\x1b[32mINFO\x1b[0m'
  };
  return colors[severity] || severity;
}

export function formatAnalysisResults(results: AnalysisResult[]): string {
  if (results.length === 0) {
    return '\n\x1b[32m✓ No vulnerabilities detected\x1b[0m\n';
  }
  
  const bySeverity: Record<Severity, AnalysisResult[]> = {
    [Severity.Critical]: [],
    [Severity.High]: [],
    [Severity.Medium]: [],
    [Severity.Low]: [],
    [Severity.Info]: []
  };
  
  for (const result of results) {
    bySeverity[result.severity].push(result);
  }
  
  let output = '\n';
  output += '═'.repeat(70) + '\n';
  output += 'SECURITY ANALYSIS RESULTS\n';
  output += '═'.repeat(70) + '\n\n';
  
  const severityOrder: Severity[] = [
    Severity.Critical,
    Severity.High,
    Severity.Medium,
    Severity.Low,
    Severity.Info
  ];
  
  for (const severity of severityOrder) {
    const issues = bySeverity[severity];
    if (issues.length === 0) continue;
    
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

export function truncateCode(code: string, maxLength: number = 60): string {
  const trimmed = code.trim();
  if (trimmed.length <= maxLength) {
    return trimmed;
  }
  return trimmed.substring(0, maxLength - 3) + '...';
}

export function generateSummary(results: AnalysisResult[]): {
  total: number;
  bySeverity: Record<Severity, number>;
  riskScore: number;
} {
  const bySeverity: Record<Severity, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 0,
    [Severity.Medium]: 0,
    [Severity.Low]: 0,
    [Severity.Info]: 0
  };
  
  const weights: Record<Severity, number> = {
    [Severity.Critical]: 10,
    [Severity.High]: 5,
    [Severity.Medium]: 3,
    [Severity.Low]: 1,
    [Severity.Info]: 0
  };
  
  for (const result of results) {
    bySeverity[result.severity]++;
  }
  
  let riskScore = 0;
  for (const severity of Object.keys(bySeverity) as Severity[]) {
    riskScore += bySeverity[severity] * weights[severity];
  }
  
  return {
    total: results.length,
    bySeverity,
    riskScore: Math.min(100, riskScore)
  };
}

export function formatSummary(summary: ReturnType<typeof generateSummary>): string {
  let output = '\n';
  output += '┌─────────────────────────────────────────┐\n';
  output += '│         ANALYSIS SUMMARY                │\n';
  output += '├─────────────────────────────────────────┤\n';
  output += `│ Total Issues: ${String(summary.total).padEnd(26)}│\n`;
  output += '├─────────────────────────────────────────┤\n';
  output += `│ Critical: ${String(summary.bySeverity[Severity.Critical]).padEnd(30)}│\n`;
  output += `│ High:     ${String(summary.bySeverity[Severity.High]).padEnd(30)}│\n`;
  output += `│ Medium:   ${String(summary.bySeverity[Severity.Medium]).padEnd(30)}│\n`;
  output += `│ Low:      ${String(summary.bySeverity[Severity.Low]).padEnd(30)}│\n`;
  output += `│ Info:     ${String(summary.bySeverity[Severity.Info]).padEnd(30)}│\n`;
  output += '├─────────────────────────────────────────┤\n';
  
  const riskLevel = getRiskLevel(summary.riskScore);
  const riskColor = getRiskColor(riskLevel);
  output += `│ Risk Score: ${riskColor}${String(summary.riskScore).padEnd(28)}\x1b[0m│\n`;
  output += `│ Risk Level: ${riskColor}${riskLevel.padEnd(28)}\x1b[0m│\n`;
  output += '└─────────────────────────────────────────┘\n';
  
  return output;
}

function getRiskLevel(score: number): string {
  if (score >= 80) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  if (score >= 10) return 'LOW';
  return 'MINIMAL';
}

function getRiskColor(level: string): string {
  switch (level) {
    case 'CRITICAL': return '\x1b[31m\x1b[1m';
    case 'HIGH': return '\x1b[31m';
    case 'MEDIUM': return '\x1b[33m';
    case 'LOW': return '\x1b[36m';
    default: return '\x1b[32m';
  }
}

export function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function normalizeWhitespace(code: string): string {
  return code.replace(/\s+/g, ' ').trim();
}

export function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

export function filterComments(lines: string[]): string[] {
  return lines.filter(line => !isCommentLine(line));
}

export function getContractName(content: string): string | null {
  const match = content.match(/contract\s+(\w+)/i);
  return match ? match[1] : null;
}

export function getPragmaVersion(content: string): string | null {
  const match = content.match(/pragma\s+solidity\s+([^\s;]+)/i);
  return match ? match[1] : null;
}
