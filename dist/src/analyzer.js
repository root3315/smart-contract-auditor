"use strict";
/**
 * Core analyzer module for smart contract security scanning.
 * Implements pattern-based vulnerability detection with context awareness.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SmartContractAnalyzer = void 0;
exports.createAnalyzer = createAnalyzer;
exports.analyzeContract = analyzeContract;
exports.analyzeContracts = analyzeContracts;
const patterns_1 = require("./patterns");
const utils_1 = require("./utils");
class SmartContractAnalyzer {
    constructor(options = {}) {
        this.options = {
            excludePatterns: [],
            includeWarnings: true,
            maxIssuesPerFile: 100,
            ...options
        };
        this.patterns = patterns_1.VULNERABILITY_PATTERNS;
    }
    analyzeFile(filePath) {
        const fileContent = (0, utils_1.readSolidityFile)(filePath);
        const results = this.scanContent(fileContent);
        return {
            file: filePath,
            contractName: (0, utils_1.getContractName)(fileContent.content),
            pragmaVersion: (0, utils_1.getPragmaVersion)(fileContent.content),
            results: results.slice(0, this.options.maxIssuesPerFile || 100),
            linesAnalyzed: fileContent.lines.length
        };
    }
    analyzeFiles(filePaths) {
        const files = [];
        for (const filePath of filePaths) {
            try {
                const analysis = this.analyzeFile(filePath);
                files.push(analysis);
            }
            catch (error) {
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
    scanContent(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        for (let i = 0; i < lines.length; i++) {
            const lineNumber = i + 1;
            const line = lines[i];
            if ((0, utils_1.isCommentLine)(line)) {
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
    findPatternMatch(line, pattern) {
        for (const regex of pattern.patterns) {
            if (regex.test(line)) {
                return true;
            }
        }
        return false;
    }
    analyzeContext(content, lineIndex, pattern) {
        if (!pattern.contextPatterns || pattern.contextPatterns.length === 0) {
            return { hasContext: false, contextLines: [] };
        }
        const lines = content.split(/\r?\n/);
        const contextLines = [];
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
    shouldSkipPattern(pattern) {
        if (!this.options.includeWarnings && pattern.severity === patterns_1.Severity.Info) {
            return true;
        }
        if (this.options.excludePatterns) {
            return this.options.excludePatterns.includes(pattern.type);
        }
        return false;
    }
    shouldReportIssue(pattern, context) {
        if (pattern.contextPatterns && pattern.contextPatterns.length > 0) {
            if (pattern.type === patterns_1.VulnerabilityType.AccessControl) {
                return !context.hasContext;
            }
            if (pattern.type === patterns_1.VulnerabilityType.UnprotectedFunction) {
                return !context.hasContext;
            }
            if (pattern.type === patterns_1.VulnerabilityType.UnprotectedInitialize) {
                return !context.hasContext;
            }
            if (pattern.type === patterns_1.VulnerabilityType.UnsafeERC20) {
                return !context.hasContext;
            }
            if (pattern.type === patterns_1.VulnerabilityType.MissingFallback) {
                return !context.hasContext;
            }
        }
        return true;
    }
    detectReentrancyPatterns(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
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
                            type: patterns_1.VulnerabilityType.Reentrancy,
                            severity: patterns_1.Severity.Critical,
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
    detectAccessControlIssues(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
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
                            type: patterns_1.VulnerabilityType.AccessControl,
                            severity: patterns_1.Severity.High,
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
    detectDelegateCallIssues(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
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
                            type: patterns_1.VulnerabilityType.DelegateCall,
                            severity: patterns_1.Severity.Critical,
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
    detectTxOriginIssues(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const txOriginPattern = /tx\.origin/i;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            if (txOriginPattern.test(line)) {
                results.push({
                    type: patterns_1.VulnerabilityType.TxOrigin,
                    severity: patterns_1.Severity.High,
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
    detectSignatureMalleabilityIssues(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const ecrecoverPattern = /ecrecover\s*\(/i;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            if (ecrecoverPattern.test(line)) {
                results.push({
                    type: patterns_1.VulnerabilityType.SignatureMalleability,
                    severity: patterns_1.Severity.High,
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
    detectUnsafeERC20Issues(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const unsafeTransferPattern = /(?:IERC20|token)\s*\([^)]+\)\.transfer(?:From)?\s*\(/i;
        const safeERC20Pattern = /using\s+SafeERC20|SafeERC20/i;
        const hasSafeERC20 = lines.some(line => safeERC20Pattern.test(line));
        if (hasSafeERC20)
            return results;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            if (unsafeTransferPattern.test(line)) {
                results.push({
                    type: patterns_1.VulnerabilityType.UnsafeERC20,
                    severity: patterns_1.Severity.Medium,
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
    detectUnprotectedInitialize(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
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
                            type: patterns_1.VulnerabilityType.UnprotectedInitialize,
                            severity: patterns_1.Severity.Critical,
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
    detectMissingZeroCheck(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
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
                            type: patterns_1.VulnerabilityType.MissingZeroCheck,
                            severity: patterns_1.Severity.Medium,
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
    detectHardcodedAddresses(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const hardcodedAddressPattern = /0x[0-9a-fA-F]{40}/;
        const constantPattern = /constant|immutable/i;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            const match = line.match(hardcodedAddressPattern);
            if (match) {
                const isConstant = constantPattern.test(line);
                if (!isConstant) {
                    results.push({
                        type: patterns_1.VulnerabilityType.HardcodedAddress,
                        severity: patterns_1.Severity.Medium,
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
    detectUnsafeCast(fileContent) {
        const results = [];
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
            if ((0, utils_1.isCommentLine)(line))
                continue;
            for (const pattern of unsafeCastPatterns) {
                if (pattern.test(line)) {
                    results.push({
                        type: patterns_1.VulnerabilityType.UnsafeCast,
                        severity: patterns_1.Severity.Medium,
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
    detectShadowing(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const stateVars = (0, utils_1.findStateVariables)(fileContent.content);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            const funcMatch = line.match(/function\s+\w+\s*\(([^)]*)\)/i);
            if (funcMatch && funcMatch[1]) {
                const params = funcMatch[1];
                const paramNames = params.match(/(?:address|uint|int|bool|string|bytes\d*)\s+(\w+)/gi);
                if (paramNames) {
                    for (const param of paramNames) {
                        const paramName = param.split(/\s+/)[1];
                        if (paramName && stateVars.includes(paramName)) {
                            results.push({
                                type: patterns_1.VulnerabilityType.Shadowing,
                                severity: patterns_1.Severity.Low,
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
    detectMissingFallback(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const payableFunctionPattern = /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*payable/i;
        const receivePattern = /receive\s*\(\s*\)\s*(?:external)?\s*payable/i;
        const fallbackPattern = /fallback\s*\(\s*\)\s*(?:external)?\s*(?:payable)?/i;
        const hasPayableFunction = lines.some(line => payableFunctionPattern.test(line));
        const hasReceive = lines.some(line => receivePattern.test(line));
        const hasFallback = lines.some(line => fallbackPattern.test(line));
        if (hasPayableFunction && !hasReceive && !hasFallback) {
            results.push({
                type: patterns_1.VulnerabilityType.MissingFallback,
                severity: patterns_1.Severity.Low,
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
    detectEtherLoss(fileContent) {
        const results = [];
        const lines = fileContent.lines;
        const etherLossPatterns = [
            /address\s*\([^)]+\)\.balance\s*=\s*\d+/i,
            /balance\s*=\s*0\s*;/i
        ];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            if ((0, utils_1.isCommentLine)(line))
                continue;
            for (const pattern of etherLossPatterns) {
                if (pattern.test(line)) {
                    results.push({
                        type: patterns_1.VulnerabilityType.EtherLoss,
                        severity: patterns_1.Severity.Critical,
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
    deduplicateResults(results) {
        const seen = new Set();
        const unique = [];
        for (const result of results) {
            const key = `${result.type}:${result.line}:${result.code.substring(0, 50)}`;
            if (!seen.has(key)) {
                seen.add(key);
                unique.push(result);
            }
        }
        return unique.sort((a, b) => {
            const severityOrder = {
                [patterns_1.Severity.Critical]: 0,
                [patterns_1.Severity.High]: 1,
                [patterns_1.Severity.Medium]: 2,
                [patterns_1.Severity.Low]: 3,
                [patterns_1.Severity.Info]: 4
            };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }
    addCustomPattern(pattern) {
        this.patterns.push(pattern);
    }
    removePattern(type) {
        this.patterns = this.patterns.filter(p => p.type !== type);
    }
    getPatterns() {
        return [...this.patterns];
    }
}
exports.SmartContractAnalyzer = SmartContractAnalyzer;
function createAnalyzer(options) {
    return new SmartContractAnalyzer(options);
}
function analyzeContract(filePath) {
    const analyzer = createAnalyzer();
    return analyzer.analyzeFile(filePath);
}
function analyzeContracts(filePaths) {
    const analyzer = createAnalyzer();
    return analyzer.analyzeFiles(filePaths);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5hbHl6ZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvYW5hbHl6ZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOzs7R0FHRzs7O0FBNjBCSCx3Q0FFQztBQUVELDBDQUdDO0FBRUQsNENBR0M7QUF2MUJELHlDQU1vQjtBQUNwQixtQ0FTaUI7QUFzQmpCLE1BQWEscUJBQXFCO0lBSWhDLFlBQVksVUFBMkIsRUFBRTtRQUN2QyxJQUFJLENBQUMsT0FBTyxHQUFHO1lBQ2IsZUFBZSxFQUFFLEVBQUU7WUFDbkIsZUFBZSxFQUFFLElBQUk7WUFDckIsZ0JBQWdCLEVBQUUsR0FBRztZQUNyQixHQUFHLE9BQU87U0FDWCxDQUFDO1FBQ0YsSUFBSSxDQUFDLFFBQVEsR0FBRyxpQ0FBc0IsQ0FBQztJQUN6QyxDQUFDO0lBRUQsV0FBVyxDQUFDLFFBQWdCO1FBQzFCLE1BQU0sV0FBVyxHQUFHLElBQUEsd0JBQWdCLEVBQUMsUUFBUSxDQUFDLENBQUM7UUFDL0MsTUFBTSxPQUFPLEdBQUcsSUFBSSxDQUFDLFdBQVcsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUU5QyxPQUFPO1lBQ0wsSUFBSSxFQUFFLFFBQVE7WUFDZCxZQUFZLEVBQUUsSUFBQSx1QkFBZSxFQUFDLFdBQVcsQ0FBQyxPQUFPLENBQUM7WUFDbEQsYUFBYSxFQUFFLElBQUEsd0JBQWdCLEVBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQztZQUNwRCxPQUFPLEVBQUUsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxnQkFBZ0IsSUFBSSxHQUFHLENBQUM7WUFDL0QsYUFBYSxFQUFFLFdBQVcsQ0FBQyxLQUFLLENBQUMsTUFBTTtTQUN4QyxDQUFDO0lBQ0osQ0FBQztJQUVELFlBQVksQ0FBQyxTQUFtQjtRQUM5QixNQUFNLEtBQUssR0FBbUIsRUFBRSxDQUFDO1FBRWpDLEtBQUssTUFBTSxRQUFRLElBQUksU0FBUyxFQUFFLENBQUM7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QUFFRCxTQUFnQixlQUFlLENBQUMsUUFBZ0I7SUFDOUMsTUFBTSxRQUFRLEdBQUcsY0FBYyxFQUFFLENBQUM7SUFDbEMsT0FBTyxRQUFRLENBQUMsV0FBVyxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ3hDLENBQUM7QUFFRCxTQUFnQixnQkFBZ0IsQ0FBQyxTQUFtQjtJQUNsRCxNQUFNLFFBQVEsR0FBRyxjQUFjLEVBQUUsQ0FBQztJQUNsQyxPQUFPLFFBQVEsQ0FBQyxZQUFZLENBQUMsU0FBUyxDQUFDLENBQUM7QUFDMUMsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQ29yZSBhbmFseXplciBtb2R1bGUgZm9yIHNtYXJ0IGNvbnRyYWN0IHNlY3VyaXR5IHNjYW5uaW5nLlxuICogSW1wbGVtZW50cyBwYXR0ZXJuLWJhc2VkIHZ1bG5lcmFiaWxpdHkgZGV0ZWN0aW9uIHdpdGggY29udGV4dCBhd2FyZW5lc3MuXG4gKi9cblxuaW1wb3J0IHtcbiAgVnVsbmVyYWJpbGl0eVBhdHRlcm4sXG4gIFZ1bG5lcmFiaWxpdHlUeXBlLFxuICBTZXZlcml0eSxcbiAgQW5hbHlzaXNSZXN1bHQsXG4gIFZVTE5FUkFCSUxJVFlfUEFUVEVSTlNcbn0gZnJvbSAnLi9wYXR0ZXJucyc7XG5pbXBvcnQge1xuICBGaWxlQ29udGVudCxcbiAgcmVhZFNvbGlkaXR5RmlsZSxcbiAgaXNDb21tZW50TGluZSxcbiAgZ2V0Q29udHJhY3ROYW1lLFxuICBnZXRQcmFnbWFWZXJzaW9uLFxuICBleHRyYWN0RnVuY3Rpb25Cb2R5LFxuICBoYXNNb2RpZmllcixcbiAgZmluZFN0YXRlVmFyaWFibGVzXG59IGZyb20gJy4vdXRpbHMnO1xuXG5leHBvcnQgaW50ZXJmYWNlIEFuYWx5emVyT3B0aW9ucyB7XG4gIGV4Y2x1ZGVQYXR0ZXJucz86IHN0cmluZ1tdO1xuICBpbmNsdWRlV2FybmluZ3M/OiBib29sZWFuO1xuICBtYXhJc3N1ZXNQZXJGaWxlPzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZpbGVBbmFseXNpcyB7XG4gIGZpbGU6IHN0cmluZztcbiAgY29udHJhY3ROYW1lOiBzdHJpbmcgfCBudWxsO1xuICBwcmFnbWFWZXJzaW9uOiBzdHJpbmcgfCBudWxsO1xuICByZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdO1xuICBsaW5lc0FuYWx5emVkOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQW5hbHlzaXNSZXBvcnQge1xuICBmaWxlczogRmlsZUFuYWx5c2lzW107XG4gIHRvdGFsSXNzdWVzOiBudW1iZXI7XG4gIHRpbWVzdGFtcDogc3RyaW5nO1xufVxuXG5leHBvcnQgY2xhc3MgU21hcnRDb250cmFjdEFuYWx5emVyIHtcbiAgcHJpdmF0ZSBvcHRpb25zOiBBbmFseXplck9wdGlvbnM7XG4gIHByaXZhdGUgcGF0dGVybnM6IFZ1bG5lcmFiaWxpdHlQYXR0ZXJuW107XG5cbiAgY29uc3RydWN0b3Iob3B0aW9uczogQW5hbHl6ZXJPcHRpb25zID0ge30pIHtcbiAgICB0aGlzLm9wdGlvbnMgPSB7XG4gICAgICBleGNsdWRlUGF0dGVybnM6IFtdLFxuICAgICAgaW5jbHVkZVdhcm5pbmdzOiB0cnVlLFxuICAgICAgbWF4SXNzdWVzUGVyRmlsZTogMTAwLFxuICAgICAgLi4ub3B0aW9uc1xuICAgIH07XG4gICAgdGhpcy5wYXR0ZXJucyA9IFZVTE5FUkFCSUxJVFlfUEFUVEVSTlM7XG4gIH1cblxuICBhbmFseXplRmlsZShmaWxlUGF0aDogc3RyaW5nKTogRmlsZUFuYWx5c2lzIHtcbiAgICBjb25zdCBmaWxlQ29udGVudCA9IHJlYWRTb2xpZGl0eUZpbGUoZmlsZVBhdGgpO1xuICAgIGNvbnN0IHJlc3VsdHMgPSB0aGlzLnNjYW5Db250ZW50KGZpbGVDb250ZW50KTtcblxuICAgIHJldHVybiB7XG4gICAgICBmaWxlOiBmaWxlUGF0aCxcbiAgICAgIGNvbnRyYWN0TmFtZTogZ2V0Q29udHJhY3ROYW1lKGZpbGVDb250ZW50LmNvbnRlbnQpLFxuICAgICAgcHJhZ21hVmVyc2lvbjogZ2V0UHJhZ21hVmVyc2lvbihmaWxlQ29udGVudC5jb250ZW50KSxcbiAgICAgIHJlc3VsdHM6IHJlc3VsdHMuc2xpY2UoMCwgdGhpcy5vcHRpb25zLm1heElzc3Vlc1BlckZpbGUgfHwgMTAwKSxcbiAgICAgIGxpbmVzQW5hbHl6ZWQ6IGZpbGVDb250ZW50LmxpbmVzLmxlbmd0aFxuICAgIH07XG4gIH1cblxuICBhbmFseXplRmlsZXMoZmlsZVBhdGhzOiBzdHJpbmdbXSk6IEFuYWx5c2lzUmVwb3J0IHtcbiAgICBjb25zdCBmaWxlczogRmlsZUFuYWx5c2lzW10gPSBbXTtcblxuICAgIGZvciAoY29uc3QgZmlsZVBhdGggb2YgZmlsZVBhdGhzKSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBhbmFseXNpcyA9IHRoaXMuYW5hbHl6ZUZpbGUoZmlsZVBhdGgpO1xuICAgICAgICBmaWxlcy5wdXNoKGFuYWx5c2lzKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogJ1Vua25vd24gZXJyb3InO1xuICAgICAgICBmaWxlcy5wdXNoKHtcbiAgICAgICAgICBmaWxlOiBmaWxlUGF0aCxcbiAgICAgICAgICBjb250cmFjdE5hbWU6IG51bGwsXG4gICAgICAgICAgcHJhZ21hVmVyc2lvbjogbnVsbCxcbiAgICAgICAgICByZXN1bHRzOiBbXSxcbiAgICAgICAgICBsaW5lc0FuYWx5emVkOiAwXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IHRvdGFsSXNzdWVzID0gZmlsZXMucmVkdWNlKChzdW0sIGYpID0+IHN1bSArIGYucmVzdWx0cy5sZW5ndGgsIDApO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGZpbGVzLFxuICAgICAgdG90YWxJc3N1ZXMsXG4gICAgICB0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKVxuICAgIH07XG4gIH1cblxuICBwcml2YXRlIHNjYW5Db250ZW50KGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgbGluZU51bWJlciA9IGkgKyAxO1xuICAgICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuXG4gICAgICBpZiAoaXNDb21tZW50TGluZShsaW5lKSkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgZm9yIChjb25zdCBwYXR0ZXJuIG9mIHRoaXMucGF0dGVybnMpIHtcbiAgICAgICAgaWYgKHRoaXMuc2hvdWxkU2tpcFBhdHRlcm4ocGF0dGVybikpIHtcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG1hdGNoID0gdGhpcy5maW5kUGF0dGVybk1hdGNoKGxpbmUsIHBhdHRlcm4pO1xuICAgICAgICBpZiAobWF0Y2gpIHtcbiAgICAgICAgICBjb25zdCBjb250ZXh0ID0gdGhpcy5hbmFseXplQ29udGV4dChmaWxlQ29udGVudC5jb250ZW50LCBpLCBwYXR0ZXJuKTtcblxuICAgICAgICAgIGlmICh0aGlzLnNob3VsZFJlcG9ydElzc3VlKHBhdHRlcm4sIGNvbnRleHQpKSB7XG4gICAgICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgICAgICB0eXBlOiBwYXR0ZXJuLnR5cGUsXG4gICAgICAgICAgICAgIHNldmVyaXR5OiBwYXR0ZXJuLnNldmVyaXR5LFxuICAgICAgICAgICAgICBuYW1lOiBwYXR0ZXJuLm5hbWUsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBwYXR0ZXJuLmRlc2NyaXB0aW9uLFxuICAgICAgICAgICAgICByZWNvbW1lbmRhdGlvbjogcGF0dGVybi5yZWNvbW1lbmRhdGlvbixcbiAgICAgICAgICAgICAgbGluZTogbGluZU51bWJlcixcbiAgICAgICAgICAgICAgY29kZTogbGluZS50cmltKCksXG4gICAgICAgICAgICAgIGZpbGU6IGZpbGVDb250ZW50LnBhdGhcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdFJlZW50cmFuY3lQYXR0ZXJucyhmaWxlQ29udGVudCkpO1xuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdEFjY2Vzc0NvbnRyb2xJc3N1ZXMoZmlsZUNvbnRlbnQpKTtcbiAgICByZXN1bHRzLnB1c2goLi4udGhpcy5kZXRlY3REZWxlZ2F0ZUNhbGxJc3N1ZXMoZmlsZUNvbnRlbnQpKTtcbiAgICByZXN1bHRzLnB1c2goLi4udGhpcy5kZXRlY3RUeE9yaWdpbklzc3VlcyhmaWxlQ29udGVudCkpO1xuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdFNpZ25hdHVyZU1hbGxlYWJpbGl0eUlzc3VlcyhmaWxlQ29udGVudCkpO1xuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdFVuc2FmZUVSQzIwSXNzdWVzKGZpbGVDb250ZW50KSk7XG4gICAgcmVzdWx0cy5wdXNoKC4uLnRoaXMuZGV0ZWN0VW5wcm90ZWN0ZWRJbml0aWFsaXplKGZpbGVDb250ZW50KSk7XG4gICAgcmVzdWx0cy5wdXNoKC4uLnRoaXMuZGV0ZWN0TWlzc2luZ1plcm9DaGVjayhmaWxlQ29udGVudCkpO1xuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdEhhcmRjb2RlZEFkZHJlc3NlcyhmaWxlQ29udGVudCkpO1xuICAgIHJlc3VsdHMucHVzaCguLi50aGlzLmRldGVjdFVuc2FmZUNhc3QoZmlsZUNvbnRlbnQpKTtcbiAgICByZXN1bHRzLnB1c2goLi4udGhpcy5kZXRlY3RTaGFkb3dpbmcoZmlsZUNvbnRlbnQpKTtcbiAgICByZXN1bHRzLnB1c2goLi4udGhpcy5kZXRlY3RNaXNzaW5nRmFsbGJhY2soZmlsZUNvbnRlbnQpKTtcbiAgICByZXN1bHRzLnB1c2goLi4udGhpcy5kZXRlY3RFdGhlckxvc3MoZmlsZUNvbnRlbnQpKTtcblxuICAgIHJldHVybiB0aGlzLmRlZHVwbGljYXRlUmVzdWx0cyhyZXN1bHRzKTtcbiAgfVxuXG4gIHByaXZhdGUgZmluZFBhdHRlcm5NYXRjaChsaW5lOiBzdHJpbmcsIHBhdHRlcm46IFZ1bG5lcmFiaWxpdHlQYXR0ZXJuKTogYm9vbGVhbiB7XG4gICAgZm9yIChjb25zdCByZWdleCBvZiBwYXR0ZXJuLnBhdHRlcm5zKSB7XG4gICAgICBpZiAocmVnZXgudGVzdChsaW5lKSkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgcHJpdmF0ZSBhbmFseXplQ29udGV4dChcbiAgICBjb250ZW50OiBzdHJpbmcsXG4gICAgbGluZUluZGV4OiBudW1iZXIsXG4gICAgcGF0dGVybjogVnVsbmVyYWJpbGl0eVBhdHRlcm5cbiAgKTogeyBoYXNDb250ZXh0OiBib29sZWFuOyBjb250ZXh0TGluZXM6IHN0cmluZ1tdIH0ge1xuICAgIGlmICghcGF0dGVybi5jb250ZXh0UGF0dGVybnMgfHwgcGF0dGVybi5jb250ZXh0UGF0dGVybnMubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4geyBoYXNDb250ZXh0OiBmYWxzZSwgY29udGV4dExpbmVzOiBbXSB9O1xuICAgIH1cblxuICAgIGNvbnN0IGxpbmVzID0gY29udGVudC5zcGxpdCgvXFxyP1xcbi8pO1xuICAgIGNvbnN0IGNvbnRleHRMaW5lczogc3RyaW5nW10gPSBbXTtcbiAgICBjb25zdCBzZWFyY2hSYW5nZSA9IE1hdGgubWluKDUwLCBsaW5lcy5sZW5ndGgpO1xuICAgIGNvbnN0IHN0YXJ0SW5kZXggPSBNYXRoLm1heCgwLCBsaW5lSW5kZXggLSBzZWFyY2hSYW5nZSk7XG4gICAgY29uc3QgZW5kSW5kZXggPSBNYXRoLm1pbihsaW5lcy5sZW5ndGgsIGxpbmVJbmRleCArIHNlYXJjaFJhbmdlKTtcblxuICAgIGZvciAobGV0IGkgPSBzdGFydEluZGV4OyBpIDwgZW5kSW5kZXg7IGkrKykge1xuICAgICAgZm9yIChjb25zdCBjdHhQYXR0ZXJuIG9mIHBhdHRlcm4uY29udGV4dFBhdHRlcm5zKSB7XG4gICAgICAgIGlmIChjdHhQYXR0ZXJuLnRlc3QobGluZXNbaV0pKSB7XG4gICAgICAgICAgY29udGV4dExpbmVzLnB1c2gobGluZXNbaV0udHJpbSgpKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICBoYXNDb250ZXh0OiBjb250ZXh0TGluZXMubGVuZ3RoID4gMCxcbiAgICAgIGNvbnRleHRMaW5lc1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIHNob3VsZFNraXBQYXR0ZXJuKHBhdHRlcm46IFZ1bG5lcmFiaWxpdHlQYXR0ZXJuKTogYm9vbGVhbiB7XG4gICAgaWYgKCF0aGlzLm9wdGlvbnMuaW5jbHVkZVdhcm5pbmdzICYmIHBhdHRlcm4uc2V2ZXJpdHkgPT09IFNldmVyaXR5LkluZm8pIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIGlmICh0aGlzLm9wdGlvbnMuZXhjbHVkZVBhdHRlcm5zKSB7XG4gICAgICByZXR1cm4gdGhpcy5vcHRpb25zLmV4Y2x1ZGVQYXR0ZXJucy5pbmNsdWRlcyhwYXR0ZXJuLnR5cGUpO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIHByaXZhdGUgc2hvdWxkUmVwb3J0SXNzdWUoXG4gICAgcGF0dGVybjogVnVsbmVyYWJpbGl0eVBhdHRlcm4sXG4gICAgY29udGV4dDogeyBoYXNDb250ZXh0OiBib29sZWFuOyBjb250ZXh0TGluZXM6IHN0cmluZ1tdIH1cbiAgKTogYm9vbGVhbiB7XG4gICAgaWYgKHBhdHRlcm4uY29udGV4dFBhdHRlcm5zICYmIHBhdHRlcm4uY29udGV4dFBhdHRlcm5zLmxlbmd0aCA+IDApIHtcbiAgICAgIGlmIChwYXR0ZXJuLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLkFjY2Vzc0NvbnRyb2wpIHtcbiAgICAgICAgcmV0dXJuICFjb250ZXh0Lmhhc0NvbnRleHQ7XG4gICAgICB9XG5cbiAgICAgIGlmIChwYXR0ZXJuLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkRnVuY3Rpb24pIHtcbiAgICAgICAgcmV0dXJuICFjb250ZXh0Lmhhc0NvbnRleHQ7XG4gICAgICB9XG5cbiAgICAgIGlmIChwYXR0ZXJuLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkSW5pdGlhbGl6ZSkge1xuICAgICAgICByZXR1cm4gIWNvbnRleHQuaGFzQ29udGV4dDtcbiAgICAgIH1cblxuICAgICAgaWYgKHBhdHRlcm4udHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuVW5zYWZlRVJDMjApIHtcbiAgICAgICAgcmV0dXJuICFjb250ZXh0Lmhhc0NvbnRleHQ7XG4gICAgICB9XG5cbiAgICAgIGlmIChwYXR0ZXJuLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLk1pc3NpbmdGYWxsYmFjaykge1xuICAgICAgICByZXR1cm4gIWNvbnRleHQuaGFzQ29udGV4dDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIHByaXZhdGUgZGV0ZWN0UmVlbnRyYW5jeVBhdHRlcm5zKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgbGV0IGluVnVsbmVyYWJsZUZ1bmN0aW9uID0gZmFsc2U7XG4gICAgbGV0IGZ1bmN0aW9uU3RhcnRMaW5lID0gMDtcbiAgICBsZXQgaGFzU3RhdGVXcml0ZSA9IGZhbHNlO1xuICAgIGxldCBoYXNFeHRlcm5hbENhbGwgPSBmYWxzZTtcbiAgICBsZXQgZXh0ZXJuYWxDYWxsTGluZSA9IDA7XG5cbiAgICBjb25zdCBzdGF0ZUNoYW5nZVBhdHRlcm4gPSAvKD86XFx3K1xccyo9XFxzKnxlbWl0XFxzK1xcdyt8c2VsZmRlc3RydWN0KS9pO1xuICAgIGNvbnN0IGV4dGVybmFsQ2FsbFBhdHRlcm4gPSAvXFwuKD86Y2FsbHxzZW5kfHRyYW5zZmVyfGRlbGVnYXRlY2FsbClcXHMqXFwoL2k7XG4gICAgY29uc3QgZnVuY3Rpb25QYXR0ZXJuID0gL2Z1bmN0aW9uXFxzK1xcdytcXHMqXFwoW14pXSpcXClcXHMqKD86ZXh0ZXJuYWx8cHVibGljKS9pO1xuICAgIGNvbnN0IGZ1bmN0aW9uRW5kUGF0dGVybiA9IC9eXFxzKlxcfVxccyokLztcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBsaW5lc1tpXTtcbiAgICAgIGNvbnN0IGxpbmVOdW1iZXIgPSBpICsgMTtcblxuICAgICAgaWYgKGlzQ29tbWVudExpbmUobGluZSkpIGNvbnRpbnVlO1xuXG4gICAgICBpZiAoZnVuY3Rpb25QYXR0ZXJuLnRlc3QobGluZSkpIHtcbiAgICAgICAgaW5WdWxuZXJhYmxlRnVuY3Rpb24gPSB0cnVlO1xuICAgICAgICBmdW5jdGlvblN0YXJ0TGluZSA9IGxpbmVOdW1iZXI7XG4gICAgICAgIGhhc1N0YXRlV3JpdGUgPSBmYWxzZTtcbiAgICAgICAgaGFzRXh0ZXJuYWxDYWxsID0gZmFsc2U7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoaW5WdWxuZXJhYmxlRnVuY3Rpb24pIHtcbiAgICAgICAgaWYgKGZ1bmN0aW9uRW5kUGF0dGVybi50ZXN0KGxpbmUpKSB7XG4gICAgICAgICAgaWYgKGhhc0V4dGVybmFsQ2FsbCAmJiBoYXNTdGF0ZVdyaXRlICYmIGV4dGVybmFsQ2FsbExpbmUgPCBmdW5jdGlvblN0YXJ0TGluZSArIDUpIHtcbiAgICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlJlZW50cmFuY3ksXG4gICAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5Dcml0aWNhbCxcbiAgICAgICAgICAgICAgbmFtZTogJ1BvdGVudGlhbCBSZWVudHJhbmN5IChTdGF0ZS1CZWZvcmUtQ2FsbCknLFxuICAgICAgICAgICAgICBkZXNjcmlwdGlvbjogJ0V4dGVybmFsIGNhbGwgbWFkZSBiZWZvcmUgc3RhdGUgY2hhbmdlcyBpbiBmdW5jdGlvbicsXG4gICAgICAgICAgICAgIHJlY29tbWVuZGF0aW9uOiAnRm9sbG93IGNoZWNrcy1lZmZlY3RzLWludGVyYWN0aW9ucyBwYXR0ZXJuJyxcbiAgICAgICAgICAgICAgbGluZTogZXh0ZXJuYWxDYWxsTGluZSxcbiAgICAgICAgICAgICAgY29kZTogbGluZXNbZXh0ZXJuYWxDYWxsTGluZSAtIDFdLnRyaW0oKSxcbiAgICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGluVnVsbmVyYWJsZUZ1bmN0aW9uID0gZmFsc2U7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoc3RhdGVDaGFuZ2VQYXR0ZXJuLnRlc3QobGluZSkgJiYgIWhhc1N0YXRlV3JpdGUpIHtcbiAgICAgICAgICBoYXNTdGF0ZVdyaXRlID0gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChleHRlcm5hbENhbGxQYXR0ZXJuLnRlc3QobGluZSkgJiYgIWhhc0V4dGVybmFsQ2FsbCkge1xuICAgICAgICAgIGhhc0V4dGVybmFsQ2FsbCA9IHRydWU7XG4gICAgICAgICAgZXh0ZXJuYWxDYWxsTGluZSA9IGxpbmVOdW1iZXI7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcmVzdWx0cztcbiAgfVxuXG4gIHByaXZhdGUgZGV0ZWN0QWNjZXNzQ29udHJvbElzc3VlcyhmaWxlQ29udGVudDogRmlsZUNvbnRlbnQpOiBBbmFseXNpc1Jlc3VsdFtdIHtcbiAgICBjb25zdCByZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdID0gW107XG4gICAgY29uc3QgbGluZXMgPSBmaWxlQ29udGVudC5saW5lcztcblxuICAgIGNvbnN0IGFjY2Vzc0NvbnRyb2xNb2RpZmllcnMgPSBbXG4gICAgICAvb25seU93bmVyL2ksXG4gICAgICAvb25seUFkbWluL2ksXG4gICAgICAvb25seVJvbGUvaSxcbiAgICAgIC9vbmx5QXV0aG9yaXplZC9pLFxuICAgICAgL3JlcXVpcmVzQXV0aC9pLFxuICAgICAgL21vZGlmaWVyXFxzK29ubHkvaVxuICAgIF07XG5cbiAgICBjb25zdCBkYW5nZXJvdXNGdW5jdGlvblBhdHRlcm4gPSAvZnVuY3Rpb25cXHMrXFx3K1xccypcXChbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpXFxzKig/OnBheWFibGUpP1xccypcXHsvaTtcbiAgICBjb25zdCBkYW5nZXJvdXNLZXl3b3JkcyA9IFtcbiAgICAgIC9zZWxmZGVzdHJ1Y3QvaSxcbiAgICAgIC9zdWljaWRlL2ksXG4gICAgICAvXFxib3duZXJcXHMqPS9pLFxuICAgICAgL1xcYmFkbWluXFxzKj0vaSxcbiAgICAgIC93aXRoZHJhdy9pLFxuICAgICAgL3RyYW5zZmVyT3duZXJzaGlwL2lcbiAgICBdO1xuXG4gICAgbGV0IGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICBsZXQgZnVuY3Rpb25TdGFydExpbmUgPSAwO1xuICAgIGxldCBoYXNBY2Nlc3NDb250cm9sID0gZmFsc2U7XG4gICAgbGV0IGlzRGFuZ2Vyb3VzID0gZmFsc2U7XG4gICAgbGV0IGZ1bmN0aW9uTGluZSA9ICcnO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuICAgICAgY29uc3QgbGluZU51bWJlciA9IGkgKyAxO1xuXG4gICAgICBpZiAoaXNDb21tZW50TGluZShsaW5lKSkgY29udGludWU7XG5cbiAgICAgIGlmIChkYW5nZXJvdXNGdW5jdGlvblBhdHRlcm4udGVzdChsaW5lKSkge1xuICAgICAgICBpbkZ1bmN0aW9uID0gdHJ1ZTtcbiAgICAgICAgZnVuY3Rpb25TdGFydExpbmUgPSBsaW5lTnVtYmVyO1xuICAgICAgICBoYXNBY2Nlc3NDb250cm9sID0gZmFsc2U7XG4gICAgICAgIGlzRGFuZ2Vyb3VzID0gZmFsc2U7XG4gICAgICAgIGZ1bmN0aW9uTGluZSA9IGxpbmU7XG5cbiAgICAgICAgZm9yIChjb25zdCBtb2RpZmllciBvZiBhY2Nlc3NDb250cm9sTW9kaWZpZXJzKSB7XG4gICAgICAgICAgaWYgKG1vZGlmaWVyLnRlc3QobGluZSkpIHtcbiAgICAgICAgICAgIGhhc0FjY2Vzc0NvbnRyb2wgPSB0cnVlO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZm9yIChjb25zdCBrZXl3b3JkIG9mIGRhbmdlcm91c0tleXdvcmRzKSB7XG4gICAgICAgICAgaWYgKGtleXdvcmQudGVzdChsaW5lKSkge1xuICAgICAgICAgICAgaXNEYW5nZXJvdXMgPSB0cnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKGluRnVuY3Rpb24pIHtcbiAgICAgICAgZm9yIChjb25zdCBtb2RpZmllciBvZiBhY2Nlc3NDb250cm9sTW9kaWZpZXJzKSB7XG4gICAgICAgICAgaWYgKG1vZGlmaWVyLnRlc3QobGluZSkpIHtcbiAgICAgICAgICAgIGhhc0FjY2Vzc0NvbnRyb2wgPSB0cnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAoY29uc3Qga2V5d29yZCBvZiBkYW5nZXJvdXNLZXl3b3Jkcykge1xuICAgICAgICAgIGlmIChrZXl3b3JkLnRlc3QobGluZSkpIHtcbiAgICAgICAgICAgIGlzRGFuZ2Vyb3VzID0gdHJ1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoL15cXHMqXFx9XFxzKiQvLnRlc3QobGluZSkpIHtcbiAgICAgICAgICBpZiAoaXNEYW5nZXJvdXMgJiYgIWhhc0FjY2Vzc0NvbnRyb2wpIHtcbiAgICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkFjY2Vzc0NvbnRyb2wsXG4gICAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5IaWdoLFxuICAgICAgICAgICAgICBuYW1lOiAnTWlzc2luZyBBY2Nlc3MgQ29udHJvbCBvbiBDcml0aWNhbCBGdW5jdGlvbicsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiAnRnVuY3Rpb24gcGVyZm9ybXMgc2Vuc2l0aXZlIG9wZXJhdGlvbiB3aXRob3V0IGFjY2VzcyBjb250cm9sJyxcbiAgICAgICAgICAgICAgcmVjb21tZW5kYXRpb246ICdBZGQgYXBwcm9wcmlhdGUgYWNjZXNzIGNvbnRyb2wgbW9kaWZpZXInLFxuICAgICAgICAgICAgICBsaW5lOiBmdW5jdGlvblN0YXJ0TGluZSxcbiAgICAgICAgICAgICAgY29kZTogZnVuY3Rpb25MaW5lLnRyaW0oKSxcbiAgICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXN1bHRzO1xuICB9XG5cbiAgcHJpdmF0ZSBkZXRlY3REZWxlZ2F0ZUNhbGxJc3N1ZXMoZmlsZUNvbnRlbnQ6IEZpbGVDb250ZW50KTogQW5hbHlzaXNSZXN1bHRbXSB7XG4gICAgY29uc3QgcmVzdWx0czogQW5hbHlzaXNSZXN1bHRbXSA9IFtdO1xuICAgIGNvbnN0IGxpbmVzID0gZmlsZUNvbnRlbnQubGluZXM7XG5cbiAgICBjb25zdCBkZWxlZ2F0ZUNhbGxQYXR0ZXJuID0gL1xcLmRlbGVnYXRlY2FsbFxccypcXCgvaTtcbiAgICBjb25zdCBmdW5jdGlvblBhdHRlcm4gPSAvZnVuY3Rpb25cXHMrXFx3K1xccypcXChbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpL2k7XG4gICAgY29uc3QgZnVuY3Rpb25FbmRQYXR0ZXJuID0gL15cXHMqXFx9XFxzKiQvO1xuXG4gICAgbGV0IGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICBsZXQgZnVuY3Rpb25TdGFydExpbmUgPSAwO1xuICAgIGxldCBoYXNEZWxlZ2F0ZUNhbGwgPSBmYWxzZTtcbiAgICBsZXQgZGVsZWdhdGVDYWxsTGluZSA9IDA7XG4gICAgbGV0IGRlbGVnYXRlQ2FsbENvZGUgPSAnJztcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBsaW5lc1tpXTtcbiAgICAgIGNvbnN0IGxpbmVOdW1iZXIgPSBpICsgMTtcblxuICAgICAgaWYgKGlzQ29tbWVudExpbmUobGluZSkpIGNvbnRpbnVlO1xuXG4gICAgICBpZiAoZnVuY3Rpb25QYXR0ZXJuLnRlc3QobGluZSkpIHtcbiAgICAgICAgaW5GdW5jdGlvbiA9IHRydWU7XG4gICAgICAgIGZ1bmN0aW9uU3RhcnRMaW5lID0gbGluZU51bWJlcjtcbiAgICAgICAgaGFzRGVsZWdhdGVDYWxsID0gZmFsc2U7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoaW5GdW5jdGlvbikge1xuICAgICAgICBpZiAoZnVuY3Rpb25FbmRQYXR0ZXJuLnRlc3QobGluZSkpIHtcbiAgICAgICAgICBpZiAoaGFzRGVsZWdhdGVDYWxsKSB7XG4gICAgICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgICAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5EZWxlZ2F0ZUNhbGwsXG4gICAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5Dcml0aWNhbCxcbiAgICAgICAgICAgICAgbmFtZTogJ1Vuc2FmZSBEZWxlZ2F0ZWNhbGwgVXNhZ2UnLFxuICAgICAgICAgICAgICBkZXNjcmlwdGlvbjogJ0Z1bmN0aW9uIHVzZXMgZGVsZWdhdGVjYWxsIHdoaWNoIGNhbiBsZWFkIHRvIGNvbnRyYWN0IHRha2VvdmVyJyxcbiAgICAgICAgICAgICAgcmVjb21tZW5kYXRpb246ICdSZXN0cmljdCBkZWxlZ2F0ZWNhbGwgdG8gdHJ1c3RlZCBhZGRyZXNzZXM7IGF2b2lkIHVzZXItY29udHJvbGxlZCB0YXJnZXRzJyxcbiAgICAgICAgICAgICAgbGluZTogZGVsZWdhdGVDYWxsTGluZSxcbiAgICAgICAgICAgICAgY29kZTogZGVsZWdhdGVDYWxsQ29kZSxcbiAgICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChkZWxlZ2F0ZUNhbGxQYXR0ZXJuLnRlc3QobGluZSkgJiYgIWhhc0RlbGVnYXRlQ2FsbCkge1xuICAgICAgICAgIGhhc0RlbGVnYXRlQ2FsbCA9IHRydWU7XG4gICAgICAgICAgZGVsZWdhdGVDYWxsTGluZSA9IGxpbmVOdW1iZXI7XG4gICAgICAgICAgZGVsZWdhdGVDYWxsQ29kZSA9IGxpbmUudHJpbSgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdFR4T3JpZ2luSXNzdWVzKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgY29uc3QgdHhPcmlnaW5QYXR0ZXJuID0gL3R4XFwub3JpZ2luL2k7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBsaW5lID0gbGluZXNbaV07XG4gICAgICBjb25zdCBsaW5lTnVtYmVyID0gaSArIDE7XG5cbiAgICAgIGlmIChpc0NvbW1lbnRMaW5lKGxpbmUpKSBjb250aW51ZTtcblxuICAgICAgaWYgKHR4T3JpZ2luUGF0dGVybi50ZXN0KGxpbmUpKSB7XG4gICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuVHhPcmlnaW4sXG4gICAgICAgICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgICAgICAgbmFtZTogJ1R4IE9yaWdpbiBBdXRoZW50aWNhdGlvbicsXG4gICAgICAgICAgZGVzY3JpcHRpb246ICdVc2luZyB0eC5vcmlnaW4gZm9yIGF1dGhlbnRpY2F0aW9uIGlzIHZ1bG5lcmFibGUgdG8gcGhpc2hpbmcgYXR0YWNrcycsXG4gICAgICAgICAgcmVjb21tZW5kYXRpb246ICdVc2UgbXNnLnNlbmRlciBpbnN0ZWFkIG9mIHR4Lm9yaWdpbiBmb3IgYXV0aGVudGljYXRpb24nLFxuICAgICAgICAgIGxpbmU6IGxpbmVOdW1iZXIsXG4gICAgICAgICAgY29kZTogbGluZS50cmltKCksXG4gICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcmVzdWx0cztcbiAgfVxuXG4gIHByaXZhdGUgZGV0ZWN0U2lnbmF0dXJlTWFsbGVhYmlsaXR5SXNzdWVzKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgY29uc3QgZWNyZWNvdmVyUGF0dGVybiA9IC9lY3JlY292ZXJcXHMqXFwoL2k7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBsaW5lID0gbGluZXNbaV07XG4gICAgICBjb25zdCBsaW5lTnVtYmVyID0gaSArIDE7XG5cbiAgICAgIGlmIChpc0NvbW1lbnRMaW5lKGxpbmUpKSBjb250aW51ZTtcblxuICAgICAgaWYgKGVjcmVjb3ZlclBhdHRlcm4udGVzdChsaW5lKSkge1xuICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlNpZ25hdHVyZU1hbGxlYWJpbGl0eSxcbiAgICAgICAgICBzZXZlcml0eTogU2V2ZXJpdHkuSGlnaCxcbiAgICAgICAgICBuYW1lOiAnU2lnbmF0dXJlIE1hbGxlYWJpbGl0eSBSaXNrJyxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0VDRFNBIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24gbWF5IGJlIHZ1bG5lcmFibGUgdG8gbWFsbGVhYmlsaXR5IGF0dGFja3MnLFxuICAgICAgICAgIHJlY29tbWVuZGF0aW9uOiAnVXNlIE9wZW5aZXBwZWxpbiBFQ0RTQSBsaWJyYXJ5IHdpdGggcHJvcGVyIHNpZ25hdHVyZSB2YWxpZGF0aW9uJyxcbiAgICAgICAgICBsaW5lOiBsaW5lTnVtYmVyLFxuICAgICAgICAgIGNvZGU6IGxpbmUudHJpbSgpLFxuICAgICAgICAgIGZpbGU6IGZpbGVDb250ZW50LnBhdGhcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdFVuc2FmZUVSQzIwSXNzdWVzKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgY29uc3QgdW5zYWZlVHJhbnNmZXJQYXR0ZXJuID0gLyg/OklFUkMyMHx0b2tlbilcXHMqXFwoW14pXStcXClcXC50cmFuc2Zlcig/OkZyb20pP1xccypcXCgvaTtcbiAgICBjb25zdCBzYWZlRVJDMjBQYXR0ZXJuID0gL3VzaW5nXFxzK1NhZmVFUkMyMHxTYWZlRVJDMjAvaTtcbiAgICBjb25zdCBoYXNTYWZlRVJDMjAgPSBsaW5lcy5zb21lKGxpbmUgPT4gc2FmZUVSQzIwUGF0dGVybi50ZXN0KGxpbmUpKTtcblxuICAgIGlmIChoYXNTYWZlRVJDMjApIHJldHVybiByZXN1bHRzO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuICAgICAgY29uc3QgbGluZU51bWJlciA9IGkgKyAxO1xuXG4gICAgICBpZiAoaXNDb21tZW50TGluZShsaW5lKSkgY29udGludWU7XG5cbiAgICAgIGlmICh1bnNhZmVUcmFuc2ZlclBhdHRlcm4udGVzdChsaW5lKSkge1xuICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVuc2FmZUVSQzIwLFxuICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgICAgICAgbmFtZTogJ1Vuc2FmZSBFUkMyMCBPcGVyYXRpb25zJyxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ1VzaW5nIHRyYW5zZmVyL3RyYW5zZmVyRnJvbSB3aXRob3V0IFNhZmVFUkMyMCBsaWJyYXJ5JyxcbiAgICAgICAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBTYWZlRVJDMjAgbGlicmFyeSBmb3IgdG9rZW4gb3BlcmF0aW9ucycsXG4gICAgICAgICAgbGluZTogbGluZU51bWJlcixcbiAgICAgICAgICBjb2RlOiBsaW5lLnRyaW0oKSxcbiAgICAgICAgICBmaWxlOiBmaWxlQ29udGVudC5wYXRoXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXN1bHRzO1xuICB9XG5cbiAgcHJpdmF0ZSBkZXRlY3RVbnByb3RlY3RlZEluaXRpYWxpemUoZmlsZUNvbnRlbnQ6IEZpbGVDb250ZW50KTogQW5hbHlzaXNSZXN1bHRbXSB7XG4gICAgY29uc3QgcmVzdWx0czogQW5hbHlzaXNSZXN1bHRbXSA9IFtdO1xuICAgIGNvbnN0IGxpbmVzID0gZmlsZUNvbnRlbnQubGluZXM7XG5cbiAgICBjb25zdCBpbml0aWFsaXplUGF0dGVybiA9IC9mdW5jdGlvblxccysoPzppbml0aWFsaXplfGluaXR8aW5pdGlhbGl6ZVZcXGQqKVxccypcXChbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpL2k7XG4gICAgY29uc3QgaW5pdGlhbGl6ZXJNb2RpZmllciA9IC9vbmx5SW5pdGlhbGl6aW5nfG9ubHlQcm94eXxpbml0aWFsaXplci9pO1xuXG4gICAgbGV0IGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICBsZXQgZnVuY3Rpb25TdGFydExpbmUgPSAwO1xuICAgIGxldCBoYXNJbml0aWFsaXplck1vZGlmaWVyID0gZmFsc2U7XG4gICAgbGV0IGZ1bmN0aW9uTGluZSA9ICcnO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuICAgICAgY29uc3QgbGluZU51bWJlciA9IGkgKyAxO1xuXG4gICAgICBpZiAoaXNDb21tZW50TGluZShsaW5lKSkgY29udGludWU7XG5cbiAgICAgIGlmIChpbml0aWFsaXplUGF0dGVybi50ZXN0KGxpbmUpKSB7XG4gICAgICAgIGluRnVuY3Rpb24gPSB0cnVlO1xuICAgICAgICBmdW5jdGlvblN0YXJ0TGluZSA9IGxpbmVOdW1iZXI7XG4gICAgICAgIGhhc0luaXRpYWxpemVyTW9kaWZpZXIgPSBpbml0aWFsaXplck1vZGlmaWVyLnRlc3QobGluZSk7XG4gICAgICAgIGZ1bmN0aW9uTGluZSA9IGxpbmU7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoaW5GdW5jdGlvbikge1xuICAgICAgICBpZiAoaW5pdGlhbGl6ZXJNb2RpZmllci50ZXN0KGxpbmUpKSB7XG4gICAgICAgICAgaGFzSW5pdGlhbGl6ZXJNb2RpZmllciA9IHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoL15cXHMqXFx9XFxzKiQvLnRlc3QobGluZSkpIHtcbiAgICAgICAgICBpZiAoIWhhc0luaXRpYWxpemVyTW9kaWZpZXIpIHtcbiAgICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkSW5pdGlhbGl6ZSxcbiAgICAgICAgICAgICAgc2V2ZXJpdHk6IFNldmVyaXR5LkNyaXRpY2FsLFxuICAgICAgICAgICAgICBuYW1lOiAnVW5wcm90ZWN0ZWQgSW5pdGlhbGl6ZSBGdW5jdGlvbicsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiAnSW5pdGlhbGl6ZSBmdW5jdGlvbiBsYWNrcyBhY2Nlc3MgY29udHJvbCBtb2RpZmllcicsXG4gICAgICAgICAgICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIG9ubHlJbml0aWFsaXppbmcgb3IgaW5pdGlhbGl6ZXIgbW9kaWZpZXInLFxuICAgICAgICAgICAgICBsaW5lOiBmdW5jdGlvblN0YXJ0TGluZSxcbiAgICAgICAgICAgICAgY29kZTogZnVuY3Rpb25MaW5lLnRyaW0oKSxcbiAgICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiByZXN1bHRzO1xuICB9XG5cbiAgcHJpdmF0ZSBkZXRlY3RNaXNzaW5nWmVyb0NoZWNrKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgY29uc3QgYWRkcmVzc1BhcmFtUGF0dGVybiA9IC9mdW5jdGlvblxccytcXHcrXFxzKlxcKFteKV0qYWRkcmVzc1xccysoXFx3KylbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpL2k7XG4gICAgY29uc3QgemVyb0NoZWNrUGF0dGVybiA9IC8hPVxccyphZGRyZXNzXFxzKlxcKFxccyowXFxzKlxcKXwhPVxccyphZGRyZXNzMC9pO1xuXG4gICAgbGV0IGluRnVuY3Rpb24gPSBmYWxzZTtcbiAgICBsZXQgZnVuY3Rpb25TdGFydExpbmUgPSAwO1xuICAgIGxldCBoYXNaZXJvQ2hlY2sgPSBmYWxzZTtcbiAgICBsZXQgcGFyYW1OYW1lID0gJyc7XG4gICAgbGV0IGZ1bmN0aW9uTGluZSA9ICcnO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaW5lcy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgbGluZSA9IGxpbmVzW2ldO1xuICAgICAgY29uc3QgbGluZU51bWJlciA9IGkgKyAxO1xuXG4gICAgICBpZiAoaXNDb21tZW50TGluZShsaW5lKSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IG1hdGNoID0gbGluZS5tYXRjaChhZGRyZXNzUGFyYW1QYXR0ZXJuKTtcbiAgICAgIGlmIChtYXRjaCkge1xuICAgICAgICBpbkZ1bmN0aW9uID0gdHJ1ZTtcbiAgICAgICAgZnVuY3Rpb25TdGFydExpbmUgPSBsaW5lTnVtYmVyO1xuICAgICAgICBwYXJhbU5hbWUgPSBtYXRjaFsxXTtcbiAgICAgICAgaGFzWmVyb0NoZWNrID0gemVyb0NoZWNrUGF0dGVybi50ZXN0KGxpbmUpO1xuICAgICAgICBmdW5jdGlvbkxpbmUgPSBsaW5lO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKGluRnVuY3Rpb24pIHtcbiAgICAgICAgaWYgKHplcm9DaGVja1BhdHRlcm4udGVzdChsaW5lKSkge1xuICAgICAgICAgIGhhc1plcm9DaGVjayA9IHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoL15cXHMqXFx9XFxzKiQvLnRlc3QobGluZSkpIHtcbiAgICAgICAgICBpZiAoIWhhc1plcm9DaGVjayAmJiBwYXJhbU5hbWUpIHtcbiAgICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLk1pc3NpbmdaZXJvQ2hlY2ssXG4gICAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgICAgICAgICAgIG5hbWU6ICdNaXNzaW5nIFplcm8gQWRkcmVzcyBDaGVjaycsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgRnVuY3Rpb24gcGFyYW1ldGVyICcke3BhcmFtTmFtZX0nIGlzIG5vdCB2YWxpZGF0ZWQgYWdhaW5zdCB6ZXJvIGFkZHJlc3NgLFxuICAgICAgICAgICAgICByZWNvbW1lbmRhdGlvbjogJ0FkZCByZXF1aXJlIHN0YXRlbWVudCB0byB2YWxpZGF0ZSBhZGRyZXNzIGlzIG5vdCB6ZXJvJyxcbiAgICAgICAgICAgICAgbGluZTogZnVuY3Rpb25TdGFydExpbmUsXG4gICAgICAgICAgICAgIGNvZGU6IGZ1bmN0aW9uTGluZS50cmltKCksXG4gICAgICAgICAgICAgIGZpbGU6IGZpbGVDb250ZW50LnBhdGhcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpbkZ1bmN0aW9uID0gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcmVzdWx0cztcbiAgfVxuXG4gIHByaXZhdGUgZGV0ZWN0SGFyZGNvZGVkQWRkcmVzc2VzKGZpbGVDb250ZW50OiBGaWxlQ29udGVudCk6IEFuYWx5c2lzUmVzdWx0W10ge1xuICAgIGNvbnN0IHJlc3VsdHM6IEFuYWx5c2lzUmVzdWx0W10gPSBbXTtcbiAgICBjb25zdCBsaW5lcyA9IGZpbGVDb250ZW50LmxpbmVzO1xuXG4gICAgY29uc3QgaGFyZGNvZGVkQWRkcmVzc1BhdHRlcm4gPSAvMHhbMC05YS1mQS1GXXs0MH0vO1xuICAgIGNvbnN0IGNvbnN0YW50UGF0dGVybiA9IC9jb25zdGFudHxpbW11dGFibGUvaTtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBsaW5lc1tpXTtcbiAgICAgIGNvbnN0IGxpbmVOdW1iZXIgPSBpICsgMTtcblxuICAgICAgaWYgKGlzQ29tbWVudExpbmUobGluZSkpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBtYXRjaCA9IGxpbmUubWF0Y2goaGFyZGNvZGVkQWRkcmVzc1BhdHRlcm4pO1xuICAgICAgaWYgKG1hdGNoKSB7XG4gICAgICAgIGNvbnN0IGlzQ29uc3RhbnQgPSBjb25zdGFudFBhdHRlcm4udGVzdChsaW5lKTtcbiAgICAgICAgaWYgKCFpc0NvbnN0YW50KSB7XG4gICAgICAgICAgcmVzdWx0cy5wdXNoKHtcbiAgICAgICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkhhcmRjb2RlZEFkZHJlc3MsXG4gICAgICAgICAgICBzZXZlcml0eTogU2V2ZXJpdHkuTWVkaXVtLFxuICAgICAgICAgICAgbmFtZTogJ0hhcmRjb2RlZCBBZGRyZXNzJyxcbiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiAnSGFyZGNvZGVkIGFkZHJlc3MgZm91bmQgdGhhdCBtYXkgaW5kaWNhdGUgYmFja2Rvb3JzIG9yIHJlZHVjZSBmbGV4aWJpbGl0eScsXG4gICAgICAgICAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBjb25maWd1cmFibGUgYWRkcmVzc2VzIG9yIGRvY3VtZW50IHRoZSBwdXJwb3NlIGNsZWFybHknLFxuICAgICAgICAgICAgbGluZTogbGluZU51bWJlcixcbiAgICAgICAgICAgIGNvZGU6IGxpbmUudHJpbSgpLFxuICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdFVuc2FmZUNhc3QoZmlsZUNvbnRlbnQ6IEZpbGVDb250ZW50KTogQW5hbHlzaXNSZXN1bHRbXSB7XG4gICAgY29uc3QgcmVzdWx0czogQW5hbHlzaXNSZXN1bHRbXSA9IFtdO1xuICAgIGNvbnN0IGxpbmVzID0gZmlsZUNvbnRlbnQubGluZXM7XG5cbiAgICBjb25zdCB1bnNhZmVDYXN0UGF0dGVybnMgPSBbXG4gICAgICAvdWludFxcZCpcXHMqXFwoXFxzKnVpbnRcXGQrXFxzKlxcKS9pLFxuICAgICAgL2ludFxcZCpcXHMqXFwoXFxzKmludFxcZCtcXHMqXFwpL2ksXG4gICAgICAvYWRkcmVzc1xccypcXChcXHMqdWludC9pLFxuICAgICAgL3VpbnRcXHMqXFwoXFxzKmludC9pXG4gICAgXTtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBsaW5lc1tpXTtcbiAgICAgIGNvbnN0IGxpbmVOdW1iZXIgPSBpICsgMTtcblxuICAgICAgaWYgKGlzQ29tbWVudExpbmUobGluZSkpIGNvbnRpbnVlO1xuXG4gICAgICBmb3IgKGNvbnN0IHBhdHRlcm4gb2YgdW5zYWZlQ2FzdFBhdHRlcm5zKSB7XG4gICAgICAgIGlmIChwYXR0ZXJuLnRlc3QobGluZSkpIHtcbiAgICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuVW5zYWZlQ2FzdCxcbiAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgICAgICAgICBuYW1lOiAnVW5zYWZlIFR5cGUgQ2FzdGluZycsXG4gICAgICAgICAgICBkZXNjcmlwdGlvbjogJ1R5cGUgY2FzdGluZyBtYXkgdHJ1bmNhdGUgZGF0YSBvciBjYXVzZSB1bmV4cGVjdGVkIGJlaGF2aW9yJyxcbiAgICAgICAgICAgIHJlY29tbWVuZGF0aW9uOiAnRW5zdXJlIHR5cGUgY2FzdHMgYXJlIHNhZmUgYW5kIGRvIG5vdCBsb3NlIGRhdGEnLFxuICAgICAgICAgICAgbGluZTogbGluZU51bWJlcixcbiAgICAgICAgICAgIGNvZGU6IGxpbmUudHJpbSgpLFxuICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdFNoYWRvd2luZyhmaWxlQ29udGVudDogRmlsZUNvbnRlbnQpOiBBbmFseXNpc1Jlc3VsdFtdIHtcbiAgICBjb25zdCByZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdID0gW107XG4gICAgY29uc3QgbGluZXMgPSBmaWxlQ29udGVudC5saW5lcztcblxuICAgIGNvbnN0IHN0YXRlVmFycyA9IGZpbmRTdGF0ZVZhcmlhYmxlcyhmaWxlQ29udGVudC5jb250ZW50KTtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IGxpbmUgPSBsaW5lc1tpXTtcbiAgICAgIGNvbnN0IGxpbmVOdW1iZXIgPSBpICsgMTtcblxuICAgICAgaWYgKGlzQ29tbWVudExpbmUobGluZSkpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBmdW5jTWF0Y2ggPSBsaW5lLm1hdGNoKC9mdW5jdGlvblxccytcXHcrXFxzKlxcKChbXildKilcXCkvaSk7XG4gICAgICBpZiAoZnVuY01hdGNoICYmIGZ1bmNNYXRjaFsxXSkge1xuICAgICAgICBjb25zdCBwYXJhbXMgPSBmdW5jTWF0Y2hbMV07XG4gICAgICAgIGNvbnN0IHBhcmFtTmFtZXMgPSBwYXJhbXMubWF0Y2goLyg/OmFkZHJlc3N8dWludHxpbnR8Ym9vbHxzdHJpbmd8Ynl0ZXNcXGQqKVxccysoXFx3KykvZ2kpO1xuICAgICAgICBcbiAgICAgICAgaWYgKHBhcmFtTmFtZXMpIHtcbiAgICAgICAgICBmb3IgKGNvbnN0IHBhcmFtIG9mIHBhcmFtTmFtZXMpIHtcbiAgICAgICAgICAgIGNvbnN0IHBhcmFtTmFtZSA9IHBhcmFtLnNwbGl0KC9cXHMrLylbMV07XG4gICAgICAgICAgICBpZiAocGFyYW1OYW1lICYmIHN0YXRlVmFycy5pbmNsdWRlcyhwYXJhbU5hbWUpKSB7XG4gICAgICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICAgICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuU2hhZG93aW5nLFxuICAgICAgICAgICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5Mb3csXG4gICAgICAgICAgICAgICAgbmFtZTogJ1ZhcmlhYmxlIFNoYWRvd2luZycsXG4gICAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGBQYXJhbWV0ZXIgJyR7cGFyYW1OYW1lfScgc2hhZG93cyBhIHN0YXRlIHZhcmlhYmxlYCxcbiAgICAgICAgICAgICAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBkaWZmZXJlbnQgbmFtZXMgZm9yIHBhcmFtZXRlcnMgdG8gYXZvaWQgc2hhZG93aW5nJyxcbiAgICAgICAgICAgICAgICBsaW5lOiBsaW5lTnVtYmVyLFxuICAgICAgICAgICAgICAgIGNvZGU6IGxpbmUudHJpbSgpLFxuICAgICAgICAgICAgICAgIGZpbGU6IGZpbGVDb250ZW50LnBhdGhcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdE1pc3NpbmdGYWxsYmFjayhmaWxlQ29udGVudDogRmlsZUNvbnRlbnQpOiBBbmFseXNpc1Jlc3VsdFtdIHtcbiAgICBjb25zdCByZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdID0gW107XG4gICAgY29uc3QgbGluZXMgPSBmaWxlQ29udGVudC5saW5lcztcblxuICAgIGNvbnN0IHBheWFibGVGdW5jdGlvblBhdHRlcm4gPSAvZnVuY3Rpb25cXHMrXFx3K1xccypcXChbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpXFxzKnBheWFibGUvaTtcbiAgICBjb25zdCByZWNlaXZlUGF0dGVybiA9IC9yZWNlaXZlXFxzKlxcKFxccypcXClcXHMqKD86ZXh0ZXJuYWwpP1xccypwYXlhYmxlL2k7XG4gICAgY29uc3QgZmFsbGJhY2tQYXR0ZXJuID0gL2ZhbGxiYWNrXFxzKlxcKFxccypcXClcXHMqKD86ZXh0ZXJuYWwpP1xccyooPzpwYXlhYmxlKT8vaTtcblxuICAgIGNvbnN0IGhhc1BheWFibGVGdW5jdGlvbiA9IGxpbmVzLnNvbWUobGluZSA9PiBwYXlhYmxlRnVuY3Rpb25QYXR0ZXJuLnRlc3QobGluZSkpO1xuICAgIGNvbnN0IGhhc1JlY2VpdmUgPSBsaW5lcy5zb21lKGxpbmUgPT4gcmVjZWl2ZVBhdHRlcm4udGVzdChsaW5lKSk7XG4gICAgY29uc3QgaGFzRmFsbGJhY2sgPSBsaW5lcy5zb21lKGxpbmUgPT4gZmFsbGJhY2tQYXR0ZXJuLnRlc3QobGluZSkpO1xuXG4gICAgaWYgKGhhc1BheWFibGVGdW5jdGlvbiAmJiAhaGFzUmVjZWl2ZSAmJiAhaGFzRmFsbGJhY2spIHtcbiAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLk1pc3NpbmdGYWxsYmFjayxcbiAgICAgICAgc2V2ZXJpdHk6IFNldmVyaXR5LkxvdyxcbiAgICAgICAgbmFtZTogJ01pc3NpbmcgRmFsbGJhY2svUmVjZWl2ZSBGdW5jdGlvbicsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnQ29udHJhY3QgaGFzIHBheWFibGUgZnVuY3Rpb25zIGJ1dCBubyBmYWxsYmFjay9yZWNlaXZlIGZvciBkaXJlY3QgRVRIIHRyYW5zZmVycycsXG4gICAgICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIHJlY2VpdmUoKSBvciBmYWxsYmFjaygpIGZ1bmN0aW9uIGlmIGNvbnRyYWN0IHNob3VsZCBhY2NlcHQgRVRIJyxcbiAgICAgICAgbGluZTogMSxcbiAgICAgICAgY29kZTogJ2NvbnRyYWN0IGRlY2xhcmF0aW9uJyxcbiAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRldGVjdEV0aGVyTG9zcyhmaWxlQ29udGVudDogRmlsZUNvbnRlbnQpOiBBbmFseXNpc1Jlc3VsdFtdIHtcbiAgICBjb25zdCByZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdID0gW107XG4gICAgY29uc3QgbGluZXMgPSBmaWxlQ29udGVudC5saW5lcztcblxuICAgIGNvbnN0IGV0aGVyTG9zc1BhdHRlcm5zID0gW1xuICAgICAgL2FkZHJlc3NcXHMqXFwoW14pXStcXClcXC5iYWxhbmNlXFxzKj1cXHMqXFxkKy9pLFxuICAgICAgL2JhbGFuY2VcXHMqPVxccyowXFxzKjsvaVxuICAgIF07XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxpbmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBjb25zdCBsaW5lID0gbGluZXNbaV07XG4gICAgICBjb25zdCBsaW5lTnVtYmVyID0gaSArIDE7XG5cbiAgICAgIGlmIChpc0NvbW1lbnRMaW5lKGxpbmUpKSBjb250aW51ZTtcblxuICAgICAgZm9yIChjb25zdCBwYXR0ZXJuIG9mIGV0aGVyTG9zc1BhdHRlcm5zKSB7XG4gICAgICAgIGlmIChwYXR0ZXJuLnRlc3QobGluZSkpIHtcbiAgICAgICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICAgICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuRXRoZXJMb3NzLFxuICAgICAgICAgICAgc2V2ZXJpdHk6IFNldmVyaXR5LkNyaXRpY2FsLFxuICAgICAgICAgICAgbmFtZTogJ1BvdGVudGlhbCBFdGhlciBMb3NzJyxcbiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiAnQ29kZSBtYXkgdHJhcCBvciBsb3NlIEV0aGVyIGR1ZSB0byBpbXBsZW1lbnRhdGlvbiBpc3N1ZXMnLFxuICAgICAgICAgICAgcmVjb21tZW5kYXRpb246ICdSZXZpZXcgY29udHJhY3QgZm9yIHBvdGVudGlhbCBFdGhlciB0cmFwcGluZyBzY2VuYXJpb3MnLFxuICAgICAgICAgICAgbGluZTogbGluZU51bWJlcixcbiAgICAgICAgICAgIGNvZGU6IGxpbmUudHJpbSgpLFxuICAgICAgICAgICAgZmlsZTogZmlsZUNvbnRlbnQucGF0aFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH1cblxuICBwcml2YXRlIGRlZHVwbGljYXRlUmVzdWx0cyhyZXN1bHRzOiBBbmFseXNpc1Jlc3VsdFtdKTogQW5hbHlzaXNSZXN1bHRbXSB7XG4gICAgY29uc3Qgc2VlbiA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICAgIGNvbnN0IHVuaXF1ZTogQW5hbHlzaXNSZXN1bHRbXSA9IFtdO1xuXG4gICAgZm9yIChjb25zdCByZXN1bHQgb2YgcmVzdWx0cykge1xuICAgICAgY29uc3Qga2V5ID0gYCR7cmVzdWx0LnR5cGV9OiR7cmVzdWx0LmxpbmV9OiR7cmVzdWx0LmNvZGUuc3Vic3RyaW5nKDAsIDUwKX1gO1xuICAgICAgaWYgKCFzZWVuLmhhcyhrZXkpKSB7XG4gICAgICAgIHNlZW4uYWRkKGtleSk7XG4gICAgICAgIHVuaXF1ZS5wdXNoKHJlc3VsdCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHVuaXF1ZS5zb3J0KChhLCBiKSA9PiB7XG4gICAgICBjb25zdCBzZXZlcml0eU9yZGVyOiBSZWNvcmQ8U2V2ZXJpdHksIG51bWJlcj4gPSB7XG4gICAgICAgIFtTZXZlcml0eS5Dcml0aWNhbF06IDAsXG4gICAgICAgIFtTZXZlcml0eS5IaWdoXTogMSxcbiAgICAgICAgW1NldmVyaXR5Lk1lZGl1bV06IDIsXG4gICAgICAgIFtTZXZlcml0eS5Mb3ddOiAzLFxuICAgICAgICBbU2V2ZXJpdHkuSW5mb106IDRcbiAgICAgIH07XG4gICAgICByZXR1cm4gc2V2ZXJpdHlPcmRlclthLnNldmVyaXR5XSAtIHNldmVyaXR5T3JkZXJbYi5zZXZlcml0eV07XG4gICAgfSk7XG4gIH1cblxuICBhZGRDdXN0b21QYXR0ZXJuKHBhdHRlcm46IFZ1bG5lcmFiaWxpdHlQYXR0ZXJuKTogdm9pZCB7XG4gICAgdGhpcy5wYXR0ZXJucy5wdXNoKHBhdHRlcm4pO1xuICB9XG5cbiAgcmVtb3ZlUGF0dGVybih0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZSk6IHZvaWQge1xuICAgIHRoaXMucGF0dGVybnMgPSB0aGlzLnBhdHRlcm5zLmZpbHRlcihwID0+IHAudHlwZSAhPT0gdHlwZSk7XG4gIH1cblxuICBnZXRQYXR0ZXJucygpOiBWdWxuZXJhYmlsaXR5UGF0dGVybltdIHtcbiAgICByZXR1cm4gWy4uLnRoaXMucGF0dGVybnNdO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVBbmFseXplcihvcHRpb25zPzogQW5hbHl6ZXJPcHRpb25zKTogU21hcnRDb250cmFjdEFuYWx5emVyIHtcbiAgcmV0dXJuIG5ldyBTbWFydENvbnRyYWN0QW5hbHl6ZXIob3B0aW9ucyk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBhbmFseXplQ29udHJhY3QoZmlsZVBhdGg6IHN0cmluZyk6IEZpbGVBbmFseXNpcyB7XG4gIGNvbnN0IGFuYWx5emVyID0gY3JlYXRlQW5hbHl6ZXIoKTtcbiAgcmV0dXJuIGFuYWx5emVyLmFuYWx5emVGaWxlKGZpbGVQYXRoKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGFuYWx5emVDb250cmFjdHMoZmlsZVBhdGhzOiBzdHJpbmdbXSk6IEFuYWx5c2lzUmVwb3J0IHtcbiAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICByZXR1cm4gYW5hbHl6ZXIuYW5hbHl6ZUZpbGVzKGZpbGVQYXRocyk7XG59XG4iXX0=