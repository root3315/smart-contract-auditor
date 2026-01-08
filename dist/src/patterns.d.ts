/**
 * Vulnerability patterns for smart contract security analysis.
 * Defines detection rules for common Solidity vulnerabilities.
 */
export declare enum Severity {
    Critical = "critical",
    High = "high",
    Medium = "medium",
    Low = "low",
    Info = "info"
}
export declare enum VulnerabilityType {
    Reentrancy = "reentrancy",
    IntegerOverflow = "integer_overflow",
    IntegerUnderflow = "integer_underflow",
    UncheckedExternalCall = "unchecked_external_call",
    AccessControl = "access_control",
    TimestampDependence = "timestamp_dependence",
    FrontRunning = "front_running",
    DenialOfService = "denial_of_service",
    UnprotectedFunction = "unprotected_function",
    WeakRandomness = "weak_randomness",
    DeprecatedFunction = "deprecated_function",
    UninitializedVariable = "uninitialized_variable",
    DelegateCall = "delegatecall",
    TxOrigin = "tx_origin",
    Blockhash = "blockhash",
    SignatureMalleability = "signature_malleability",
    ShortAddress = "short_address",
    HiddenOwner = "hidden_owner",
    HardcodedAddress = "hardcoded_address",
    MissingZeroCheck = "missing_zero_check",
    UnsafeERC20 = "unsafe_erc20",
    MissingEvent = "missing_event",
    UnprotectedInitialize = "unprotected_initialize",
    CentralizationRisk = "centralization_risk",
    MissingInputValidation = "missing_input_validation",
    UnsafeCast = "unsafe_cast",
    Shadowing = "shadowing",
    ConstancyIssues = "constancy_issues",
    IncorrectModifier = "incorrect_modifier",
    MissingFallback = "missing_fallback",
    EtherLoss = "ether_loss",
    InheritanceIssues = "inheritance_issues"
}
export interface VulnerabilityPattern {
    type: VulnerabilityType;
    severity: Severity;
    name: string;
    description: string;
    recommendation: string;
    patterns: RegExp[];
    contextPatterns?: RegExp[];
}
export interface AnalysisResult {
    type: VulnerabilityType;
    severity: Severity;
    name: string;
    description: string;
    recommendation: string;
    line: number;
    code: string;
    file?: string;
}
export declare const VULNERABILITY_PATTERNS: VulnerabilityPattern[];
export declare function getPatternByType(type: VulnerabilityType): VulnerabilityPattern | undefined;
export declare function getPatternsBySeverity(severity: Severity): VulnerabilityPattern[];
export declare function getAllVulnerabilityTypes(): VulnerabilityType[];
export declare function getAllSeverityLevels(): Severity[];
