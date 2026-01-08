/**
 * Core analyzer module for smart contract security scanning.
 * Implements pattern-based vulnerability detection with context awareness.
 */

import {
  VulnerabilityPattern,
  VulnerabilityType,
  Severity,
  AnalysisResult,
  VULNERABILITY_PATTERNS
} from './patterns';
import {
  FileContent,
  readSolidityFile,
  isCommentLine,
  getContractName,
  getPragmaVersion
} from './utils';

export interface AnalyzerOptions {
  excludePatterns?: string[];
  includeWarnings?: boolean;
  maxIssuesPerFile?: number;
}

export interface FileAnalysis {
  file: string;
  contractName: string | null;
  pragmaVersion: string | null;
  results: AnalysisResult[];
  linesAnalyzed: number;
}

export interface AnalysisReport {
  files: FileAnalysis[];
  totalIssues: number;
  timestamp: string;
}

export class SmartContractAnalyzer {
  private options: AnalyzerOptions;
  private patterns: VulnerabilityPattern[];

  constructor(options: AnalyzerOptions = {}) {
    this.options = {
      excludePatterns: [],
      includeWarnings: true,
      maxIssuesPerFile: 100,
      ...options
    };
    this.patterns = VULNERABILITY_PATTERNS;
  }

  analyzeFile(filePath: string): FileAnalysis {
    const fileContent = readSolidityFile(filePath);
    const results = this.scanContent(fileContent);
    
    return {
      file: filePath,
      contractName: getContractName(fileContent.content),
      pragmaVersion: getPragmaVersion(fileContent.content),
      results: results.slice(0, this.options.maxIssuesPerFile || 100),
      linesAnalyzed: fileContent.lines.length
    };
  }

  analyzeFiles(filePaths: string[]): AnalysisReport {
    const files: FileAnalysis[] = [];
    
    for (const filePath of filePaths) {
      try {
        const analysis = this.analyzeFile(filePath);
        files.push(analysis);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        files.push({
          file: filePath,
          contractName: null,
          pragmaVersion: null,
          results: [],
          linesAnalyzed: 0
        });
      }
    }
    
    const totalIssues = files.reduce((sum, f) => sum + f.results.length, 0);
    
    return {
      files,
      totalIssues,
      timestamp: new Date().toISOString()
    };
  }

  private scanContent(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;
    
    for (let i = 0; i < lines.length; i++) {
      const lineNumber = i + 1;
      const line = lines[i];
      
      if (isCommentLine(line)) {
        continue;
      }
      
      for (const pattern of this.patterns) {
        if (this.shouldSkipPattern(pattern)) {
          continue;
        }
        
        const match = this.findPatternMatch(line, pattern);
        if (match) {
          const context = this.analyzeContext(fileContent.content, i, pattern);
          
          if (this.shouldReportIssue(pattern, context)) {
            results.push({
              type: pattern.type,
              severity: pattern.severity,
              name: pattern.name,
              description: pattern.description,
              recommendation: pattern.recommendation,
              line: lineNumber,
              code: line.trim(),
              file: fileContent.path
            });
          }
        }
      }
    }
    
    results.push(...this.detectReentrancyPatterns(fileContent));
    results.push(...this.detectAccessControlIssues(fileContent));
    
    return this.deduplicateResults(results);
  }

  private findPatternMatch(line: string, pattern: VulnerabilityPattern): boolean {
    for (const regex of pattern.patterns) {
      if (regex.test(line)) {
        return true;
      }
    }
    return false;
  }

  private analyzeContext(
    content: string,
    lineIndex: number,
    pattern: VulnerabilityPattern
  ): { hasContext: boolean; contextLines: string[] } {
    if (!pattern.contextPatterns || pattern.contextPatterns.length === 0) {
      return { hasContext: false, contextLines: [] };
    }
    
    const lines = content.split(/\r?\n/);
    const contextLines: string[] = [];
    const searchRange = Math.min(50, lines.length);
    const startIndex = Math.max(0, lineIndex - searchRange);
    const endIndex = Math.min(lines.length, lineIndex + searchRange);
    
    for (let i = startIndex; i < endIndex; i++) {
      for (const ctxPattern of pattern.contextPatterns) {
        if (ctxPattern.test(lines[i])) {
          contextLines.push(lines[i].trim());
        }
      }
    }
    
    return {
      hasContext: contextLines.length > 0,
      contextLines
    };
  }

  private shouldSkipPattern(pattern: VulnerabilityPattern): boolean {
    if (!this.options.includeWarnings && pattern.severity === Severity.Info) {
      return true;
    }
    
    if (this.options.excludePatterns) {
      return this.options.excludePatterns.includes(pattern.type);
    }
    
    return false;
  }

  private shouldReportIssue(
    pattern: VulnerabilityPattern,
    context: { hasContext: boolean; contextLines: string[] }
  ): boolean {
    if (pattern.contextPatterns && pattern.contextPatterns.length > 0) {
      if (pattern.type === VulnerabilityType.AccessControl) {
        return !context.hasContext;
      }
      
      if (pattern.type === VulnerabilityType.UnprotectedFunction) {
        return !context.hasContext;
      }
    }
    
    return true;
  }

  private detectReentrancyPatterns(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;
    
    let inVulnerableFunction = false;
    let functionStartLine = 0;
    let hasStateWrite = false;
    let hasExternalCall = false;
    let externalCallLine = 0;
    
    const stateChangePattern = /(?:\w+\s*=\s*|emit\s+\w+|selfdestruct)/i;
    const externalCallPattern = /\.(?:call|send|transfer|delegatecall)\s*\(/i;
    const functionPattern = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)/i;
    const functionEndPattern = /^\s*\}\s*$/;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;
      
      if (isCommentLine(line)) continue;
      
      if (functionPattern.test(line)) {
        inVulnerableFunction = true;
        functionStartLine = lineNumber;
        hasStateWrite = false;
        hasExternalCall = false;
        continue;
      }
      
      if (inVulnerableFunction) {
        if (functionEndPattern.test(line)) {
          if (hasExternalCall && hasStateWrite && externalCallLine < functionStartLine + 5) {
            results.push({
              type: VulnerabilityType.Reentrancy,
              severity: Severity.Critical,
              name: 'Potential Reentrancy (State-Before-Call)',
              description: 'External call made before state changes in function',
              recommendation: 'Follow checks-effects-interactions pattern',
              line: externalCallLine,
              code: lines[externalCallLine - 1].trim(),
              file: fileContent.path
            });
          }
          inVulnerableFunction = false;
          continue;
        }
        
        if (stateChangePattern.test(line) && !hasStateWrite) {
          hasStateWrite = true;
        }
        
        if (externalCallPattern.test(line) && !hasExternalCall) {
          hasExternalCall = true;
          externalCallLine = lineNumber;
        }
      }
    }
    
    return results;
  }

  private detectAccessControlIssues(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;
    
    const accessControlModifiers = [
      /onlyOwner/i,
      /onlyAdmin/i,
      /onlyRole/i,
      /onlyAuthorized/i,
      /requiresAuth/i,
      /modifier\s+only/i
    ];
    
    const dangerousFunctionPattern = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?:payable)?\s*\{/i;
    const dangerousKeywords = [
      /selfdestruct/i,
      /suicide/i,
      /\bowner\s*=/i,
      /\badmin\s*=/i,
      /withdraw/i,
      /transferOwnership/i
    ];
    
    let inFunction = false;
    let functionStartLine = 0;
    let hasAccessControl = false;
    let isDangerous = false;
    let functionLine = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;
      
      if (isCommentLine(line)) continue;
      
      if (dangerousFunctionPattern.test(line)) {
        inFunction = true;
        functionStartLine = lineNumber;
        hasAccessControl = false;
        isDangerous = false;
        functionLine = line;
        
        for (const modifier of accessControlModifiers) {
          if (modifier.test(line)) {
            hasAccessControl = true;
            break;
          }
        }
        
        for (const keyword of dangerousKeywords) {
          if (keyword.test(line)) {
            isDangerous = true;
          }
        }
        continue;
      }
      
      if (inFunction) {
        for (const modifier of accessControlModifiers) {
          if (modifier.test(line)) {
            hasAccessControl = true;
          }
        }
        
        for (const keyword of dangerousKeywords) {
          if (keyword.test(line)) {
            isDangerous = true;
          }
        }
        
        if (/^\s*\}\s*$/.test(line)) {
          if (isDangerous && !hasAccessControl) {
            results.push({
              type: VulnerabilityType.AccessControl,
              severity: Severity.High,
              name: 'Missing Access Control on Critical Function',
              description: 'Function performs sensitive operation without access control',
              recommendation: 'Add appropriate access control modifier',
              line: functionStartLine,
              code: functionLine.trim(),
              file: fileContent.path
            });
          }
          inFunction = false;
        }
      }
    }
    
    return results;
  }

  private deduplicateResults(results: AnalysisResult[]): AnalysisResult[] {
    const seen = new Set<string>();
    const unique: AnalysisResult[] = [];
    
    for (const result of results) {
      const key = `${result.type}:${result.line}:${result.code.substring(0, 50)}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(result);
      }
    }
    
    return unique.sort((a, b) => {
      const severityOrder: Record<Severity, number> = {
        [Severity.Critical]: 0,
        [Severity.High]: 1,
        [Severity.Medium]: 2,
        [Severity.Low]: 3,
        [Severity.Info]: 4
      };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  addCustomPattern(pattern: VulnerabilityPattern): void {
    this.patterns.push(pattern);
  }

  removePattern(type: VulnerabilityType): void {
    this.patterns = this.patterns.filter(p => p.type !== type);
  }

  getPatterns(): VulnerabilityPattern[] {
    return [...this.patterns];
  }
}

export function createAnalyzer(options?: AnalyzerOptions): SmartContractAnalyzer {
  return new SmartContractAnalyzer(options);
}

export function analyzeContract(filePath: string): FileAnalysis {
  const analyzer = createAnalyzer();
  return analyzer.analyzeFile(filePath);
}

export function analyzeContracts(filePaths: string[]): AnalysisReport {
  const analyzer = createAnalyzer();
  return analyzer.analyzeFiles(filePaths);
}
