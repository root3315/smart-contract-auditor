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
  UninitializedVariable = 'uninitialized_variable',
  DelegateCall = 'delegatecall',
  TxOrigin = 'tx_origin',
  Blockhash = 'blockhash',
  SignatureMalleability = 'signature_malleability',
  ShortAddress = 'short_address',
  HiddenOwner = 'hidden_owner',
  HardcodedAddress = 'hardcoded_address',
  MissingZeroCheck = 'missing_zero_check',
  UnsafeERC20 = 'unsafe_erc20',
  MissingEvent = 'missing_event',
  UnprotectedInitialize = 'unprotected_initialize',
  CentralizationRisk = 'centralization_risk',
  MissingInputValidation = 'missing_input_validation',
  UnsafeCast = 'unsafe_cast',
  Shadowing = 'shadowing',
  ConstancyIssues = 'constancy_issues',
  IncorrectModifier = 'incorrect_modifier',
  MissingFallback = 'missing_fallback',
  EtherLoss = 'ether_loss',
  InheritanceIssues = 'inheritance_issues'
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
  },
  {
    type: VulnerabilityType.DelegateCall,
    severity: Severity.Critical,
    name: 'Unsafe Delegatecall',
    description: 'delegatecall to arbitrary address can lead to contract takeover',
    recommendation: 'Restrict delegatecall to trusted addresses only; avoid using with user-controlled addresses',
    patterns: [
      /delegatecall\s*\(/gi,
      /\.delegatecall\s*\(/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.TxOrigin,
    severity: Severity.High,
    name: 'Tx Origin Authentication',
    description: 'Using tx.origin for authentication is vulnerable to phishing attacks',
    recommendation: 'Use msg.sender instead of tx.origin for authentication',
    patterns: [
      /tx\.origin\s*[!=<>=]+\s*/gi,
      /require\s*\(\s*tx\.origin/gi,
      /if\s*\(\s*tx\.origin/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.Blockhash,
    severity: Severity.High,
    name: 'Blockhash Usage',
    description: 'Using blockhash for randomness or security is predictable',
    recommendation: 'Use Chainlink VRF or other secure randomness sources',
    patterns: [
      /block\.blockhash\s*\(/gi,
      /blockhash\s*\(/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.SignatureMalleability,
    severity: Severity.High,
    name: 'Signature Malleability',
    description: 'ECDSA signature may be malleable, allowing replay attacks',
    recommendation: 'Use OpenZeppelin ECDSA library with proper signature validation',
    patterns: [
      /ecrecover\s*\(/gi,
      /splitSignature\s*\(/gi,
      /\.r\s*,\s*\.s\s*,\s*\.v/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.ShortAddress,
    severity: Severity.Medium,
    name: 'Short Address Attack',
    description: 'Contract may be vulnerable to short address attack in token transfers',
    recommendation: 'Validate address length before transfer operations',
    patterns: [
      /transfer\s*\(\s*address/gi,
      /transferFrom\s*\([^)]*address/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.HiddenOwner,
    severity: Severity.High,
    name: 'Hidden Owner Pattern',
    description: 'Contract may have hidden owner functionality that can be exploited',
    recommendation: 'Review contract for hidden administrative functions',
    patterns: [
      /owner\s*=\s*tx\.origin/gi,
      /owner\s*=\s*msg\.sender/gi,
      /_owner\s*=/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.HardcodedAddress,
    severity: Severity.Medium,
    name: 'Hardcoded Address',
    description: 'Hardcoded addresses may indicate backdoors or reduce flexibility',
    recommendation: 'Use configurable addresses or constants with clear documentation',
    patterns: [
      /0x[0-9a-fA-F]{40}/gi
    ],
    contextPatterns: [
      /constant/gi,
      /immutable/gi
    ]
  },
  {
    type: VulnerabilityType.MissingZeroCheck,
    severity: Severity.Medium,
    name: 'Missing Zero Address Check',
    description: 'Function does not validate against zero address',
    recommendation: 'Add zero address validation for critical address parameters',
    patterns: [
      /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?:external|public)/gi
    ],
    contextPatterns: [
      /!=\s*address\s*\(\s*0\s*\)/gi,
      /!=\s*address0/gi
    ]
  },
  {
    type: VulnerabilityType.UnsafeERC20,
    severity: Severity.Medium,
    name: 'Unsafe ERC20 Operations',
    description: 'Using transfer/transferFrom without handling non-standard tokens',
    recommendation: 'Use SafeERC20 library for token operations',
    patterns: [
      /IERC20\s*\([^)]+\)\.transfer\s*\(/gi,
      /IERC20\s*\([^)]+\)\.transferFrom\s*\(/gi,
      /token\.transfer\s*\(/gi,
      /token\.transferFrom\s*\(/gi
    ],
    contextPatterns: [
      /SafeERC20/gi,
      /using\s+SafeERC20/gi
    ]
  },
  {
    type: VulnerabilityType.MissingEvent,
    severity: Severity.Low,
    name: 'Missing Event Emission',
    description: 'Critical state changes should emit events for off-chain tracking',
    recommendation: 'Add event emissions for important state changes',
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?:override)?\s*\{[^}]*\}/gi
    ],
    contextPatterns: [
      /emit\s+\w+/gi
    ]
  },
  {
    type: VulnerabilityType.UnprotectedInitialize,
    severity: Severity.Critical,
    name: 'Unprotected Initialize Function',
    description: 'Initialize function lacks access control, allowing anyone to initialize',
    recommendation: 'Add onlyInitializing or similar modifier to initialize functions',
    patterns: [
      /function\s+initialize\s*\(/gi,
      /function\s+init\s*\(/gi,
      /function\s+initializeV2\s*\(/gi
    ],
    contextPatterns: [
      /onlyInitializing/gi,
      /onlyProxy/gi,
      /initializer/gi
    ]
  },
  {
    type: VulnerabilityType.CentralizationRisk,
    severity: Severity.Medium,
    name: 'Centralization Risk',
    description: 'Contract has single point of control that creates centralization risk',
    recommendation: 'Consider multi-sig or DAO governance for critical functions',
    patterns: [
      /onlyOwner\s*(?:external|public)/gi,
      /function\s+\w+\s*\([^)]*\)\s*onlyOwner/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.MissingInputValidation,
    severity: Severity.Medium,
    name: 'Missing Input Validation',
    description: 'Function parameters are not properly validated',
    recommendation: 'Add require statements to validate all input parameters',
    patterns: [
      /function\s+\w+\s*\([^)]*uint[^)]*\)\s*(?:external|public)\s*\{[^}]*\}/gi
    ],
    contextPatterns: [
      /require\s*\(/gi,
      /if\s*\([^)]*<=/gi
    ]
  },
  {
    type: VulnerabilityType.UnsafeCast,
    severity: Severity.Medium,
    name: 'Unsafe Type Casting',
    description: 'Type casting may truncate data or cause unexpected behavior',
    recommendation: 'Ensure type casts are safe and do not lose data',
    patterns: [
      /uint\d*\s*\(\s*uint\d+\s*\)/gi,
      /int\d*\s*\(\s*int\d+\s*\)/gi,
      /address\s*\(\s*uint/gi,
      /uint\s*\(\s*int/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.Shadowing,
    severity: Severity.Low,
    name: 'Variable Shadowing',
    description: 'Local variable shadows state variable or function parameter',
    recommendation: 'Use different names for local variables to avoid shadowing',
    patterns: [
      /function\s+\w+\s*\([^)]*(\w+)\s+\w+[^)]*\)[^{]*\{[^}]*\b\1\b/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.ConstancyIssues,
    severity: Severity.Low,
    name: 'Constancy Issues',
    description: 'Function should be declared pure or view but is not',
    recommendation: 'Add pure or view modifier to functions that do not modify state',
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?!pure|view)\{[^}]*return[^}]*\}/gi
    ],
    contextPatterns: [
      /stateVariable\s*=/gi,
      /emit\s+/gi
    ]
  },
  {
    type: VulnerabilityType.IncorrectModifier,
    severity: Severity.Medium,
    name: 'Incorrect Modifier Usage',
    description: 'Modifier may have logic errors or be incorrectly implemented',
    recommendation: 'Review modifier logic for correctness and security',
    patterns: [
      /modifier\s+\w+\s*\([^)]*\)\s*\{[^}]*_[^}]*\}/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.MissingFallback,
    severity: Severity.Low,
    name: 'Missing Fallback Function',
    description: 'Contract may need a fallback/receive function to handle direct transfers',
    recommendation: 'Add receive() or fallback() function if contract should accept ETH',
    patterns: [
      /contract\s+\w+[^{]*\{[^}]*payable[^}]*\}/gi
    ],
    contextPatterns: [
      /receive\s*\(\s*\)/gi,
      /fallback\s*\(\s*\)/gi
    ]
  },
  {
    type: VulnerabilityType.EtherLoss,
    severity: Severity.Critical,
    name: 'Potential Ether Loss',
    description: 'Contract may trap or lose Ether due to implementation issues',
    recommendation: 'Review contract for potential Ether trapping scenarios',
    patterns: [
      /address\s*\([^)]+\)\.balance\s*=/gi,
      /balance\s*=\s*0\s*;/gi
    ],
    contextPatterns: []
  },
  {
    type: VulnerabilityType.InheritanceIssues,
    severity: Severity.Medium,
    name: 'Inheritance Order Issues',
    description: 'Contract inheritance order may cause unexpected behavior',
    recommendation: 'Review inheritance order for proper function overriding',
    patterns: [
      /contract\s+\w+\s+is\s+[^{]+\{/gi
    ],
    contextPatterns: [
      /override/gi
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
