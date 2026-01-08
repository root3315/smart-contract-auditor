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
import { SmartContractAnalyzer, createAnalyzer, analyzeContracts, AnalysisReport, AnalyzerOptions } from './analyzer';
import { VulnerabilityType, Severity } from './patterns';
export { SmartContractAnalyzer, createAnalyzer, analyzeContracts, VulnerabilityType, Severity, AnalysisReport, AnalyzerOptions };
