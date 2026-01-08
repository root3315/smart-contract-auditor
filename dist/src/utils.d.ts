/**
 * Utility functions for smart contract analysis.
 * Provides file operations, string manipulation, and formatting helpers.
 */
import { AnalysisResult, Severity } from './patterns';
export interface FileContent {
    path: string;
    content: string;
    lines: string[];
}
export declare function readSolidityFile(filePath: string): FileContent;
export declare function readDirectory(dirPath: string, extension?: string): string[];
export declare function extractLine(content: string, lineNumber: number): string;
export declare function getSurroundingLines(content: string, lineNumber: number, contextLines?: number): {
    before: string[];
    target: string;
    after: string[];
};
export declare function formatSeverity(severity: Severity): string;
export declare function formatAnalysisResults(results: AnalysisResult[]): string;
export declare function truncateCode(code: string, maxLength?: number): string;
export declare function generateSummary(results: AnalysisResult[]): {
    total: number;
    bySeverity: Record<Severity, number>;
    riskScore: number;
};
export declare function formatSummary(summary: ReturnType<typeof generateSummary>): string;
export declare function escapeRegExp(string: string): string;
export declare function normalizeWhitespace(code: string): string;
export declare function isCommentLine(line: string): boolean;
export declare function filterComments(lines: string[]): string[];
export declare function getContractName(content: string): string | null;
export declare function getPragmaVersion(content: string): string | null;
export declare function extractFunctionBody(content: string, functionName: string): string | null;
export declare function hasModifier(content: string, functionName: string, modifier: string): boolean;
export declare function findStateVariables(content: string): string[];
export declare function findFunctions(content: string): Array<{
    name: string;
    visibility: string;
    modifiers: string[];
    line: number;
}>;
export declare function isPayable(content: string): boolean;
export declare function hasConstructor(content: string): boolean;
export declare function findEvents(content: string): string[];
export declare function findModifiers(content: string): string[];
export declare function countLines(content: string): {
    total: number;
    code: number;
    comments: number;
    blank: number;
};
export declare function getInheritanceChain(content: string): string[];
export declare function isUpgradeable(content: string): boolean;
