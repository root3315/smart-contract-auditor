/**
 * Vulnerability patterns for smart contract security analysis.
 * Defines detection rules for common Solidity vulnerabilities.
 */

export enum Severity {
  Critical = 'critical',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Info = 'info'
}

export enum VulnerabilityType {
  Reentrancy = 'reentrancy',
  IntegerOverflow = 'integer_overflow',
  IntegerUnderflow = 'integer_underflow',
  UncheckedExternalCall = 'unchecked_external_call',
  AccessControl = 'access_control',
  TimestampDependence = 'timestamp_dependence',
  FrontRunning = 'front_running',
  DenialOfService = 'denial_of_service',
  UnprotectedFunction = 'unprotected_function',
  WeakRandomness = 'weak_randomness',
  DeprecatedFunction = 'deprecated_function',
  UninitializedVariable = 'uninitialized_variable'
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

export const VULNERABILITY_PATTERNS: VulnerabilityPattern[] = [
  {
    type: VulnerabilityType.Reentrancy,
    severity: Severity.Critical,
    name: 'Reentrancy Vulnerability',
    description: 'Function makes external call before updating state, allowing potential reentrancy attacks',
    recommendation: 'Use checks-effects-interactions pattern or ReentrancyGuard modifier',
    patterns: [
      /call\s*\(\s*\{[^}]*\}\s*\)/gi,
      /\.call\s*\(/gi,
      /\.send\s*\(/gi,
      /\.transfer\s*\(/gi,
      /address\s*\([^)]+\)\.transfer/gi,
      /address\s*\([^)]+\)\.send/gi,
      /address\s*\([^)]+\)\.call/gi
    ],
    contextPatterns: [
      /mapping\s*\([^)]+\)\s+\w+\s*;/gi,
      /uint\s*\w+\s*=/gi
    ]
  },
  {
    type: VulnerabilityType.IntegerOverflow,
    severity: Severity.High,
    name: 'Integer Overflow',
    description: 'Arithmetic operation may overflow without SafeMath or Solidity 0.8+ checks',
    recommendation: 'Use SafeMath library or Solidity 0.8.0+ for automatic overflow checks',
    patterns: [
      /\+\s*\w+\s*;/gi,
      /\+\s*=\s*\w+\s*;/gi,
      /\w+\s*\+\s*\w+/gi
    ],
    contextPatterns: [
      /pragma\s+solidity\s+\^?0\.[0-7]\./gi,
      /using\s+SafeMath/gi
    ]
  },
  {
    type: VulnerabilityType.IntegerUnderflow,
    severity: Severity.High,
    name: 'Integer Underflow',
    description: 'Arithmetic operation may underflow without SafeMath or Solidity 0.8+ checks',
    recommendation: 'Use SafeMath library or Solidity 0.8.0+ for automatic underflow checks',
    patterns: [
      /-\s*\w+\s*;/gi,
      /-\s*=\s*\w+\s*;/gi,
      /\w+\s*-\s*\w+/gi
    ],
    contextPatterns: [
      /pragma\s+solidity\s+\^?0\.[0-7]\./gi
    ]
  },
  {
    type: VulnerabilityType.UncheckedExternalCall,
    severity: Severity.High,
    name: 'Unchecked External Call',
    description: 'External call return value is not checked, may fail silently',
    recommendation: 'Always check the return value of low-level calls',
    patterns: [
      /\.call\s*\([^)]*\)\s*;/gi,
      /\.delegatecall\s*\([^)]*\)\s*;/gi,
      /\.staticcall\s*\([^)]*\)\s*;/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.AccessControl,
    severity: Severity.High,
    name: 'Missing Access Control',
    description: 'Critical function lacks proper access control modifiers',
    recommendation: 'Add appropriate access control modifiers (onlyOwner, onlyAdmin, etc.)',
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?:pure|view|payable)?\s*\{/gi
    ],
    contextPatterns: [
      /onlyOwner/gi,
      /onlyAdmin/gi,
      /onlyRole/gi,
      /modifier\s+only/gi
    ]
  },
  {
    type: VulnerabilityType.TimestampDependence,
    severity: Severity.Medium,
    name: 'Timestamp Dependence',
    description: 'Contract logic depends on block.timestamp which miners can manipulate',
    recommendation: 'Avoid using block.timestamp for critical logic; use block.number when possible',
    patterns: [
      /block\.timestamp/gi,
      /now\s*(?!\s*:)/gi,
      /block\.timestamp\s*[<>=!]+/gi,
      /now\s*[<>=!]+/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.FrontRunning,
    severity: Severity.Medium,
    name: 'Front-Running Vulnerability',
    description: 'Transaction may be susceptible to front-running attacks',
    recommendation: 'Use commit-reveal schemes or limit transaction impact',
    patterns: [
      /tx\.origin/gi,
      /block\.number\s*[<>=!]+/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.DenialOfService,
    severity: Severity.High,
    name: 'Potential DoS Vulnerability',
    description: 'Loop over unbounded array may cause gas exhaustion',
    recommendation: 'Avoid unbounded loops; use pull-over-push pattern',
    patterns: [
      /for\s*\(\s*(?:uint|uint256)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length/gi,
      /for\s*\(\s*(?:uint|uint256)\s+\w+\s+:\s+\w+\s+in\s+/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.UnprotectedFunction,
    severity: Severity.High,
    name: 'Unprotected Self-Destruct',
    description: 'selfdestruct can be called by anyone without access control',
    recommendation: 'Add access control modifier to selfdestruct calls',
    patterns: [
      /selfdestruct\s*\(/gi,
      /suicide\s*\(/gi
    ],
    contextPatterns: [
      /onlyOwner/gi,
      /onlyAdmin/gi
    ]
  },
  {
    type: VulnerabilityType.WeakRandomness,
    severity: Severity.High,
    name: 'Weak Randomness',
    description: 'Using block properties for randomness is predictable and insecure',
    recommendation: 'Use Chainlink VRF or other secure randomness sources',
    patterns: [
      /blockhash\s*\(/gi,
      /block\.difficulty/gi,
      /block\.prevrandao/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.DeprecatedFunction,
    severity: Severity.Low,
    name: 'Deprecated Function Usage',
    description: 'Using deprecated Solidity functions',
    recommendation: 'Update to use recommended alternatives',
    patterns: [
      /suicide\s*\(/gi,
      /sha3\s*\(/gi,
      /throw\s*;/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.UninitializedVariable,
    severity: Severity.Medium,
    name: 'Uninitialized Storage Pointer',
    description: 'Storage pointer may be uninitialized, leading to unexpected behavior',
    recommendation: 'Explicitly initialize storage variables or use memory when appropriate',
    patterns: [
      /struct\s+\w+\s+\w+\s*;/gi,
      /contract\s+\w+\s+\w+\s*;/gi
    ],
    contextPatterns: [
      /memory/gi,
      /storage/gi
    ]
  }
];

export function getPatternByType(type: VulnerabilityType): VulnerabilityPattern | undefined {
  return VULNERABILITY_PATTERNS.find(p => p.type === type);
}

export function getPatternsBySeverity(severity: Severity): VulnerabilityPattern[] {
  return VULNERABILITY_PATTERNS.filter(p => p.severity === severity);
}

export function getAllVulnerabilityTypes(): VulnerabilityType[] {
  return Object.values(VulnerabilityType);
}

export function getAllSeverityLevels(): Severity[] {
  return Object.values(Severity);
}
