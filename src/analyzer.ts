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
  getPragmaVersion,
  extractFunctionBody,
  hasModifier,
  findStateVariables
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
    results.push(...this.detectDelegateCallIssues(fileContent));
    results.push(...this.detectTxOriginIssues(fileContent));
    results.push(...this.detectSignatureMalleabilityIssues(fileContent));
    results.push(...this.detectUnsafeERC20Issues(fileContent));
    results.push(...this.detectUnprotectedInitialize(fileContent));
    results.push(...this.detectMissingZeroCheck(fileContent));
    results.push(...this.detectHardcodedAddresses(fileContent));
    results.push(...this.detectUnsafeCast(fileContent));
    results.push(...this.detectShadowing(fileContent));
    results.push(...this.detectMissingFallback(fileContent));
    results.push(...this.detectEtherLoss(fileContent));

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

      if (pattern.type === VulnerabilityType.UnprotectedInitialize) {
        return !context.hasContext;
      }

      if (pattern.type === VulnerabilityType.UnsafeERC20) {
        return !context.hasContext;
      }

      if (pattern.type === VulnerabilityType.MissingFallback) {
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

  private detectDelegateCallIssues(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const delegateCallPattern = /\.delegatecall\s*\(/i;
    const functionPattern = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)/i;
    const functionEndPattern = /^\s*\}\s*$/;

    let inFunction = false;
    let functionStartLine = 0;
    let hasDelegateCall = false;
    let delegateCallLine = 0;
    let delegateCallCode = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      if (functionPattern.test(line)) {
        inFunction = true;
        functionStartLine = lineNumber;
        hasDelegateCall = false;
        continue;
      }

      if (inFunction) {
        if (functionEndPattern.test(line)) {
          if (hasDelegateCall) {
            results.push({
              type: VulnerabilityType.DelegateCall,
              severity: Severity.Critical,
              name: 'Unsafe Delegatecall Usage',
              description: 'Function uses delegatecall which can lead to contract takeover',
              recommendation: 'Restrict delegatecall to trusted addresses; avoid user-controlled targets',
              line: delegateCallLine,
              code: delegateCallCode,
              file: fileContent.path
            });
          }
          inFunction = false;
          continue;
        }

        if (delegateCallPattern.test(line) && !hasDelegateCall) {
          hasDelegateCall = true;
          delegateCallLine = lineNumber;
          delegateCallCode = line.trim();
        }
      }
    }

    return results;
  }

  private detectTxOriginIssues(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const txOriginPattern = /tx\.origin/i;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      if (txOriginPattern.test(line)) {
        results.push({
          type: VulnerabilityType.TxOrigin,
          severity: Severity.High,
          name: 'Tx Origin Authentication',
          description: 'Using tx.origin for authentication is vulnerable to phishing attacks',
          recommendation: 'Use msg.sender instead of tx.origin for authentication',
          line: lineNumber,
          code: line.trim(),
          file: fileContent.path
        });
      }
    }

    return results;
  }

  private detectSignatureMalleabilityIssues(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const ecrecoverPattern = /ecrecover\s*\(/i;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      if (ecrecoverPattern.test(line)) {
        results.push({
          type: VulnerabilityType.SignatureMalleability,
          severity: Severity.High,
          name: 'Signature Malleability Risk',
          description: 'ECDSA signature verification may be vulnerable to malleability attacks',
          recommendation: 'Use OpenZeppelin ECDSA library with proper signature validation',
          line: lineNumber,
          code: line.trim(),
          file: fileContent.path
        });
      }
    }

    return results;
  }

  private detectUnsafeERC20Issues(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const unsafeTransferPattern = /(?:IERC20|token)\s*\([^)]+\)\.transfer(?:From)?\s*\(/i;
    const safeERC20Pattern = /using\s+SafeERC20|SafeERC20/i;
    const hasSafeERC20 = lines.some(line => safeERC20Pattern.test(line));

    if (hasSafeERC20) return results;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      if (unsafeTransferPattern.test(line)) {
        results.push({
          type: VulnerabilityType.UnsafeERC20,
          severity: Severity.Medium,
          name: 'Unsafe ERC20 Operations',
          description: 'Using transfer/transferFrom without SafeERC20 library',
          recommendation: 'Use SafeERC20 library for token operations',
          line: lineNumber,
          code: line.trim(),
          file: fileContent.path
        });
      }
    }

    return results;
  }

  private detectUnprotectedInitialize(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const initializePattern = /function\s+(?:initialize|init|initializeV\d*)\s*\([^)]*\)\s*(?:external|public)/i;
    const initializerModifier = /onlyInitializing|onlyProxy|initializer/i;

    let inFunction = false;
    let functionStartLine = 0;
    let hasInitializerModifier = false;
    let functionLine = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      if (initializePattern.test(line)) {
        inFunction = true;
        functionStartLine = lineNumber;
        hasInitializerModifier = initializerModifier.test(line);
        functionLine = line;
        continue;
      }

      if (inFunction) {
        if (initializerModifier.test(line)) {
          hasInitializerModifier = true;
        }

        if (/^\s*\}\s*$/.test(line)) {
          if (!hasInitializerModifier) {
            results.push({
              type: VulnerabilityType.UnprotectedInitialize,
              severity: Severity.Critical,
              name: 'Unprotected Initialize Function',
              description: 'Initialize function lacks access control modifier',
              recommendation: 'Add onlyInitializing or initializer modifier',
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

  private detectMissingZeroCheck(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const addressParamPattern = /function\s+\w+\s*\([^)]*address\s+(\w+)[^)]*\)\s*(?:external|public)/i;
    const zeroCheckPattern = /!=\s*address\s*\(\s*0\s*\)|!=\s*address0/i;

    let inFunction = false;
    let functionStartLine = 0;
    let hasZeroCheck = false;
    let paramName = '';
    let functionLine = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      const match = line.match(addressParamPattern);
      if (match) {
        inFunction = true;
        functionStartLine = lineNumber;
        paramName = match[1];
        hasZeroCheck = zeroCheckPattern.test(line);
        functionLine = line;
        continue;
      }

      if (inFunction) {
        if (zeroCheckPattern.test(line)) {
          hasZeroCheck = true;
        }

        if (/^\s*\}\s*$/.test(line)) {
          if (!hasZeroCheck && paramName) {
            results.push({
              type: VulnerabilityType.MissingZeroCheck,
              severity: Severity.Medium,
              name: 'Missing Zero Address Check',
              description: `Function parameter '${paramName}' is not validated against zero address`,
              recommendation: 'Add require statement to validate address is not zero',
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

  private detectHardcodedAddresses(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const hardcodedAddressPattern = /0x[0-9a-fA-F]{40}/;
    const constantPattern = /constant|immutable/i;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      const match = line.match(hardcodedAddressPattern);
      if (match) {
        const isConstant = constantPattern.test(line);
        if (!isConstant) {
          results.push({
            type: VulnerabilityType.HardcodedAddress,
            severity: Severity.Medium,
            name: 'Hardcoded Address',
            description: 'Hardcoded address found that may indicate backdoors or reduce flexibility',
            recommendation: 'Use configurable addresses or document the purpose clearly',
            line: lineNumber,
            code: line.trim(),
            file: fileContent.path
          });
        }
      }
    }

    return results;
  }

  private detectUnsafeCast(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const unsafeCastPatterns = [
      /uint\d*\s*\(\s*uint\d+\s*\)/i,
      /int\d*\s*\(\s*int\d+\s*\)/i,
      /address\s*\(\s*uint/i,
      /uint\s*\(\s*int/i
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      for (const pattern of unsafeCastPatterns) {
        if (pattern.test(line)) {
          results.push({
            type: VulnerabilityType.UnsafeCast,
            severity: Severity.Medium,
            name: 'Unsafe Type Casting',
            description: 'Type casting may truncate data or cause unexpected behavior',
            recommendation: 'Ensure type casts are safe and do not lose data',
            line: lineNumber,
            code: line.trim(),
            file: fileContent.path
          });
          break;
        }
      }
    }

    return results;
  }

  private detectShadowing(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const stateVars = findStateVariables(fileContent.content);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      const funcMatch = line.match(/function\s+\w+\s*\(([^)]*)\)/i);
      if (funcMatch && funcMatch[1]) {
        const params = funcMatch[1];
        const paramNames = params.match(/(?:address|uint|int|bool|string|bytes\d*)\s+(\w+)/gi);
        
        if (paramNames) {
          for (const param of paramNames) {
            const paramName = param.split(/\s+/)[1];
            if (paramName && stateVars.includes(paramName)) {
              results.push({
                type: VulnerabilityType.Shadowing,
                severity: Severity.Low,
                name: 'Variable Shadowing',
                description: `Parameter '${paramName}' shadows a state variable`,
                recommendation: 'Use different names for parameters to avoid shadowing',
                line: lineNumber,
                code: line.trim(),
                file: fileContent.path
              });
            }
          }
        }
      }
    }

    return results;
  }

  private detectMissingFallback(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const payableFunctionPattern = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*payable/i;
    const receivePattern = /receive\s*\(\s*\)\s*(?:external)?\s*payable/i;
    const fallbackPattern = /fallback\s*\(\s*\)\s*(?:external)?\s*(?:payable)?/i;

    const hasPayableFunction = lines.some(line => payableFunctionPattern.test(line));
    const hasReceive = lines.some(line => receivePattern.test(line));
    const hasFallback = lines.some(line => fallbackPattern.test(line));

    if (hasPayableFunction && !hasReceive && !hasFallback) {
      results.push({
        type: VulnerabilityType.MissingFallback,
        severity: Severity.Low,
        name: 'Missing Fallback/Receive Function',
        description: 'Contract has payable functions but no fallback/receive for direct ETH transfers',
        recommendation: 'Add receive() or fallback() function if contract should accept ETH',
        line: 1,
        code: 'contract declaration',
        file: fileContent.path
      });
    }

    return results;
  }

  private detectEtherLoss(fileContent: FileContent): AnalysisResult[] {
    const results: AnalysisResult[] = [];
    const lines = fileContent.lines;

    const etherLossPatterns = [
      /address\s*\([^)]+\)\.balance\s*=\s*\d+/i,
      /balance\s*=\s*0\s*;/i
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (isCommentLine(line)) continue;

      for (const pattern of etherLossPatterns) {
        if (pattern.test(line)) {
          results.push({
            type: VulnerabilityType.EtherLoss,
            severity: Severity.Critical,
            name: 'Potential Ether Loss',
            description: 'Code may trap or lose Ether due to implementation issues',
            recommendation: 'Review contract for potential Ether trapping scenarios',
            line: lineNumber,
            code: line.trim(),
            file: fileContent.path
          });
          break;
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
