/**
 * Core analyzer module for smart contract security scanning.
 * Implements pattern-based vulnerability detection with context awareness.
 */
import { VulnerabilityPattern, VulnerabilityType, AnalysisResult } from './patterns';
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
export declare class SmartContractAnalyzer {
    private options;
    private patterns;
    constructor(options?: AnalyzerOptions);
    analyzeFile(filePath: string): FileAnalysis;
    analyzeFiles(filePaths: string[]): AnalysisReport;
    private scanContent;
    private findPatternMatch;
    private analyzeContext;
    private shouldSkipPattern;
    private shouldReportIssue;
    private detectReentrancyPatterns;
    private detectAccessControlIssues;
    private detectDelegateCallIssues;
    private detectTxOriginIssues;
    private detectSignatureMalleabilityIssues;
    private detectUnsafeERC20Issues;
    private detectUnprotectedInitialize;
    private detectMissingZeroCheck;
    private detectHardcodedAddresses;
    private detectUnsafeCast;
    private detectShadowing;
    private detectMissingFallback;
    private detectEtherLoss;
    private deduplicateResults;
    addCustomPattern(pattern: VulnerabilityPattern): void;
    removePattern(type: VulnerabilityType): void;
    getPatterns(): VulnerabilityPattern[];
}
export declare function createAnalyzer(options?: AnalyzerOptions): SmartContractAnalyzer;
export declare function analyzeContract(filePath: string): FileAnalysis;
export declare function analyzeContracts(filePaths: string[]): AnalysisReport;
