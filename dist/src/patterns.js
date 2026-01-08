"use strict";
/**
 * Vulnerability patterns for smart contract security analysis.
 * Defines detection rules for common Solidity vulnerabilities.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.VULNERABILITY_PATTERNS = exports.VulnerabilityType = exports.Severity = void 0;
exports.getPatternByType = getPatternByType;
exports.getPatternsBySeverity = getPatternsBySeverity;
exports.getAllVulnerabilityTypes = getAllVulnerabilityTypes;
exports.getAllSeverityLevels = getAllSeverityLevels;
var Severity;
(function (Severity) {
    Severity["Critical"] = "critical";
    Severity["High"] = "high";
    Severity["Medium"] = "medium";
    Severity["Low"] = "low";
    Severity["Info"] = "info";
})(Severity || (exports.Severity = Severity = {}));
var VulnerabilityType;
(function (VulnerabilityType) {
    VulnerabilityType["Reentrancy"] = "reentrancy";
    VulnerabilityType["IntegerOverflow"] = "integer_overflow";
    VulnerabilityType["IntegerUnderflow"] = "integer_underflow";
    VulnerabilityType["UncheckedExternalCall"] = "unchecked_external_call";
    VulnerabilityType["AccessControl"] = "access_control";
    VulnerabilityType["TimestampDependence"] = "timestamp_dependence";
    VulnerabilityType["FrontRunning"] = "front_running";
    VulnerabilityType["DenialOfService"] = "denial_of_service";
    VulnerabilityType["UnprotectedFunction"] = "unprotected_function";
    VulnerabilityType["WeakRandomness"] = "weak_randomness";
    VulnerabilityType["DeprecatedFunction"] = "deprecated_function";
    VulnerabilityType["UninitializedVariable"] = "uninitialized_variable";
    VulnerabilityType["DelegateCall"] = "delegatecall";
    VulnerabilityType["TxOrigin"] = "tx_origin";
    VulnerabilityType["Blockhash"] = "blockhash";
    VulnerabilityType["SignatureMalleability"] = "signature_malleability";
    VulnerabilityType["ShortAddress"] = "short_address";
    VulnerabilityType["HiddenOwner"] = "hidden_owner";
    VulnerabilityType["HardcodedAddress"] = "hardcoded_address";
    VulnerabilityType["MissingZeroCheck"] = "missing_zero_check";
    VulnerabilityType["UnsafeERC20"] = "unsafe_erc20";
    VulnerabilityType["MissingEvent"] = "missing_event";
    VulnerabilityType["UnprotectedInitialize"] = "unprotected_initialize";
    VulnerabilityType["CentralizationRisk"] = "centralization_risk";
    VulnerabilityType["MissingInputValidation"] = "missing_input_validation";
    VulnerabilityType["UnsafeCast"] = "unsafe_cast";
    VulnerabilityType["Shadowing"] = "shadowing";
    VulnerabilityType["ConstancyIssues"] = "constancy_issues";
    VulnerabilityType["IncorrectModifier"] = "incorrect_modifier";
    VulnerabilityType["MissingFallback"] = "missing_fallback";
    VulnerabilityType["EtherLoss"] = "ether_loss";
    VulnerabilityType["InheritanceIssues"] = "inheritance_issues";
})(VulnerabilityType || (exports.VulnerabilityType = VulnerabilityType = {}));
exports.VULNERABILITY_PATTERNS = [
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
function getPatternByType(type) {
    return exports.VULNERABILITY_PATTERNS.find(p => p.type === type);
}
function getPatternsBySeverity(severity) {
    return exports.VULNERABILITY_PATTERNS.filter(p => p.severity === severity);
}
function getAllVulnerabilityTypes() {
    return Object.values(VulnerabilityType);
}
function getAllSeverityLevels() {
    return Object.values(Severity);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicGF0dGVybnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvcGF0dGVybnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOzs7R0FHRzs7O0FBNGZILDRDQUVDO0FBRUQsc0RBRUM7QUFFRCw0REFFQztBQUVELG9EQUVDO0FBeGdCRCxJQUFZLFFBTVg7QUFORCxXQUFZLFFBQVE7SUFDbEIsaUNBQXFCLENBQUE7SUFDckIseUJBQWEsQ0FBQTtJQUNiLDZCQUFpQixDQUFBO0lBQ2pCLHVCQUFXLENBQUE7SUFDWCx5QkFBYSxDQUFBO0FBQ2YsQ0FBQyxFQU5XLFFBQVEsd0JBQVIsUUFBUSxRQU1uQjtBQUVELElBQVksaUJBaUNYO0FBakNELFdBQVksaUJBQWlCO0lBQzNCLDhDQUF5QixDQUFBO0lBQ3pCLHlEQUFvQyxDQUFBO0lBQ3BDLDJEQUFzQyxDQUFBO0lBQ3RDLHNFQUFpRCxDQUFBO0lBQ2pELHFEQUFnQyxDQUFBO0lBQ2hDLGlFQUE0QyxDQUFBO0lBQzVDLG1EQUE4QixDQUFBO0lBQzlCLDBEQUFxQyxDQUFBO0lBQ3JDLGlFQUE0QyxDQUFBO0lBQzVDLHVEQUFrQyxDQUFBO0lBQ2xDLCtEQUEwQyxDQUFBO0lBQzFDLHFFQUFnRCxDQUFBO0lBQ2hELGtEQUE2QixDQUFBO0lBQzdCLDJDQUFzQixDQUFBO0lBQ3RCLDRDQUF1QixDQUFBO0lBQ3ZCLHFFQUFnRCxDQUFBO0lBQ2hELG1EQUE4QixDQUFBO0lBQzlCLGlEQUE0QixDQUFBO0lBQzVCLDJEQUFzQyxDQUFBO0lBQ3RDLDREQUF1QyxDQUFBO0lBQ3ZDLGlEQUE0QixDQUFBO0lBQzVCLG1EQUE4QixDQUFBO0lBQzlCLHFFQUFnRCxDQUFBO0lBQ2hELCtEQUEwQyxDQUFBO0lBQzFDLHdFQUFtRCxDQUFBO0lBQ25ELCtDQUEwQixDQUFBO0lBQzFCLDRDQUF1QixDQUFBO0lBQ3ZCLHlEQUFvQyxDQUFBO0lBQ3BDLDZEQUF3QyxDQUFBO0lBQ3hDLHlEQUFvQyxDQUFBO0lB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UUFDdkUsY0FBYyxFQUFFLHlEQUF5RDtRQUN6RSxRQUFRLEVBQUU7WUFDUixpQ0FBaUM7U0FDbEM7UUFDRCxlQUFlLEVBQUU7WUFDZixZQUFZO1NBQ2I7S0FDRjtDQUNGLENBQUM7QUFFRixTQUFnQixnQkFBZ0IsQ0FBQyxJQUF1QjtJQUN0RCxPQUFPLDhCQUFzQixDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssSUFBSSxDQUFDLENBQUM7QUFDM0QsQ0FBQztBQUVELFNBQWdCLHFCQUFxQixDQUFDLFFBQWtCO0lBQ3RELE9BQU8sOEJBQXNCLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLFFBQVEsS0FBSyxRQUFRLENBQUMsQ0FBQztBQUNyRSxDQUFDO0FBRUQsU0FBZ0Isd0JBQXdCO0lBQ3RDLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO0FBQzFDLENBQUM7QUFFRCxTQUFnQixvQkFBb0I7SUFDbEMsT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ2pDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFZ1bG5lcmFiaWxpdHkgcGF0dGVybnMgZm9yIHNtYXJ0IGNvbnRyYWN0IHNlY3VyaXR5IGFuYWx5c2lzLlxuICogRGVmaW5lcyBkZXRlY3Rpb24gcnVsZXMgZm9yIGNvbW1vbiBTb2xpZGl0eSB2dWxuZXJhYmlsaXRpZXMuXG4gKi9cblxuZXhwb3J0IGVudW0gU2V2ZXJpdHkge1xuICBDcml0aWNhbCA9ICdjcml0aWNhbCcsXG4gIEhpZ2ggPSAnaGlnaCcsXG4gIE1lZGl1bSA9ICdtZWRpdW0nLFxuICBMb3cgPSAnbG93JyxcbiAgSW5mbyA9ICdpbmZvJ1xufVxuXG5leHBvcnQgZW51bSBWdWxuZXJhYmlsaXR5VHlwZSB7XG4gIFJlZW50cmFuY3kgPSAncmVlbnRyYW5jeScsXG4gIEludGVnZXJPdmVyZmxvdyA9ICdpbnRlZ2VyX292ZXJmbG93JyxcbiAgSW50ZWdlclVuZGVyZmxvdyA9ICdpbnRlZ2VyX3VuZGVyZmxvdycsXG4gIFVuY2hlY2tlZEV4dGVybmFsQ2FsbCA9ICd1bmNoZWNrZWRfZXh0ZXJuYWxfY2FsbCcsXG4gIEFjY2Vzc0NvbnRyb2wgPSAnYWNjZXNzX2NvbnRyb2wnLFxuICBUaW1lc3RhbXBEZXBlbmRlbmNlID0gJ3RpbWVzdGFtcF9kZXBlbmRlbmNlJyxcbiAgRnJvbnRSdW5uaW5nID0gJ2Zyb250X3J1bm5pbmcnLFxuICBEZW5pYWxPZlNlcnZpY2UgPSAnZGVuaWFsX29mX3NlcnZpY2UnLFxuICBVbnByb3RlY3RlZEZ1bmN0aW9uID0gJ3VucHJvdGVjdGVkX2Z1bmN0aW9uJyxcbiAgV2Vha1JhbmRvbW5lc3MgPSAnd2Vha19yYW5kb21uZXNzJyxcbiAgRGVwcmVjYXRlZEZ1bmN0aW9uID0gJ2RlcHJlY2F0ZWRfZnVuY3Rpb24nLFxuICBVbmluaXRpYWxpemVkVmFyaWFibGUgPSAndW5pbml0aWFsaXplZF92YXJpYWJsZScsXG4gIERlbGVnYXRlQ2FsbCA9ICdkZWxlZ2F0ZWNhbGwnLFxuICBUeE9yaWdpbiA9ICd0eF9vcmlnaW4nLFxuICBCbG9ja2hhc2ggPSAnYmxvY2toYXNoJyxcbiAgU2lnbmF0dXJlTWFsbGVhYmlsaXR5ID0gJ3NpZ25hdHVyZV9tYWxsZWFiaWxpdHknLFxuICBTaG9ydEFkZHJlc3MgPSAnc2hvcnRfYWRkcmVzcycsXG4gIEhpZGRlbk93bmVyID0gJ2hpZGRlbl9vd25lcicsXG4gIEhhcmRjb2RlZEFkZHJlc3MgPSAnaGFyZGNvZGVkX2FkZHJlc3MnLFxuICBNaXNzaW5nWmVyb0NoZWNrID0gJ21pc3NpbmdfemVyb19jaGVjaycsXG4gIFVuc2FmZUVSQzIwID0gJ3Vuc2FmZV9lcmMyMCcsXG4gIE1pc3NpbmdFdmVudCA9ICdtaXNzaW5nX2V2ZW50JyxcbiAgVW5wcm90ZWN0ZWRJbml0aWFsaXplID0gJ3VucHJvdGVjdGVkX2luaXRpYWxpemUnLFxuICBDZW50cmFsaXphdGlvblJpc2sgPSAnY2VudHJhbGl6YXRpb25fcmlzaycsXG4gIE1pc3NpbmdJbnB1dFZhbGlkYXRpb24gPSAnbWlzc2luZ19pbnB1dF92YWxpZGF0aW9uJyxcbiAgVW5zYWZlQ2FzdCA9ICd1bnNhZmVfY2FzdCcsXG4gIFNoYWRvd2luZyA9ICdzaGFkb3dpbmcnLFxuICBDb25zdGFuY3lJc3N1ZXMgPSAnY29uc3RhbmN5X2lzc3VlcycsXG4gIEluY29ycmVjdE1vZGlmaWVyID0gJ2luY29ycmVjdF9tb2RpZmllcicsXG4gIE1pc3NpbmdGYWxsYmFjayA9ICdtaXNzaW5nX2ZhbGxiYWNrJyxcbiAgRXRoZXJMb3NzID0gJ2V0aGVyX2xvc3MnLFxuICBJbmhlcml0YW5jZUlzc3VlcyA9ICdpbmhlcml0YW5jZV9pc3N1ZXMnXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgVnVsbmVyYWJpbGl0eVBhdHRlcm4ge1xuICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZTtcbiAgc2V2ZXJpdHk6IFNldmVyaXR5O1xuICBuYW1lOiBzdHJpbmc7XG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG4gIHJlY29tbWVuZGF0aW9uOiBzdHJpbmc7XG4gIHBhdHRlcm5zOiBSZWdFeHBbXTtcbiAgY29udGV4dFBhdHRlcm5zPzogUmVnRXhwW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQW5hbHlzaXNSZXN1bHQge1xuICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZTtcbiAgc2V2ZXJpdHk6IFNldmVyaXR5O1xuICBuYW1lOiBzdHJpbmc7XG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG4gIHJlY29tbWVuZGF0aW9uOiBzdHJpbmc7XG4gIGxpbmU6IG51bWJlcjtcbiAgY29kZTogc3RyaW5nO1xuICBmaWxlPzogc3RyaW5nO1xufVxuXG5leHBvcnQgY29uc3QgVlVMTkVSQUJJTElUWV9QQVRURVJOUzogVnVsbmVyYWJpbGl0eVBhdHRlcm5bXSA9IFtcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlJlZW50cmFuY3ksXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkNyaXRpY2FsLFxuICAgIG5hbWU6ICdSZWVudHJhbmN5IFZ1bG5lcmFiaWxpdHknLFxuICAgIGRlc2NyaXB0aW9uOiAnRnVuY3Rpb24gbWFrZXMgZXh0ZXJuYWwgY2FsbCBiZWZvcmUgdXBkYXRpbmcgc3RhdGUsIGFsbG93aW5nIHBvdGVudGlhbCByZWVudHJhbmN5IGF0dGFja3MnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnVXNlIGNoZWNrcy1lZmZlY3RzLWludGVyYWN0aW9ucyBwYXR0ZXJuIG9yIFJlZW50cmFuY3lHdWFyZCBtb2RpZmllcicsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9jYWxsXFxzKlxcKFxccypcXHtbXn1dKlxcfVxccypcXCkvZ2ksXG4gICAgICAvXFwuY2FsbFxccypcXCgvZ2ksXG4gICAgICAvXFwuc2VuZFxccypcXCgvZ2ksXG4gICAgICAvXFwudHJhbnNmZXJcXHMqXFwoL2dpLFxuICAgICAgL2FkZHJlc3NcXHMqXFwoW14pXStcXClcXC50cmFuc2Zlci9naSxcbiAgICAgIC9hZGRyZXNzXFxzKlxcKFteKV0rXFwpXFwuc2VuZC9naSxcbiAgICAgIC9hZGRyZXNzXFxzKlxcKFteKV0rXFwpXFwuY2FsbC9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXG4gICAgICAvbWFwcGluZ1xccypcXChbXildK1xcKVxccytcXHcrXFxzKjsvZ2ksXG4gICAgICAvdWludFxccypcXHcrXFxzKj0vZ2lcbiAgICBdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5JbnRlZ2VyT3ZlcmZsb3csXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ0ludGVnZXIgT3ZlcmZsb3cnLFxuICAgIGRlc2NyaXB0aW9uOiAnQXJpdGhtZXRpYyBvcGVyYXRpb24gbWF5IG92ZXJmbG93IHdpdGhvdXQgU2FmZU1hdGggb3IgU29saWRpdHkgMC44KyBjaGVja3MnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnVXNlIFNhZmVNYXRoIGxpYnJhcnkgb3IgU29saWRpdHkgMC44LjArIGZvciBhdXRvbWF0aWMgb3ZlcmZsb3cgY2hlY2tzJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL1xcK1xccypcXHcrXFxzKjsvZ2ksXG4gICAgICAvXFwrXFxzKj1cXHMqXFx3K1xccyo7L2dpLFxuICAgICAgL1xcdytcXHMqXFwrXFxzKlxcdysvZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW1xuICAgICAgL3ByYWdtYVxccytzb2xpZGl0eVxccytcXF4/MFxcLlswLTddXFwuL2dpLFxuICAgICAgL3VzaW5nXFxzK1NhZmVNYXRoL2dpXG4gICAgXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuSW50ZWdlclVuZGVyZmxvdyxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuSGlnaCxcbiAgICBuYW1lOiAnSW50ZWdlciBVbmRlcmZsb3cnLFxuICAgIGRlc2NyaXB0aW9uOiAnQXJpdGhtZXRpYyBvcGVyYXRpb24gbWF5IHVuZGVyZmxvdyB3aXRob3V0IFNhZmVNYXRoIG9yIFNvbGlkaXR5IDAuOCsgY2hlY2tzJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBTYWZlTWF0aCBsaWJyYXJ5IG9yIFNvbGlkaXR5IDAuOC4wKyBmb3IgYXV0b21hdGljIHVuZGVyZmxvdyBjaGVja3MnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvLVxccypcXHcrXFxzKjsvZ2ksXG4gICAgICAvLVxccyo9XFxzKlxcdytcXHMqOy9naSxcbiAgICAgIC9cXHcrXFxzKi1cXHMqXFx3Ky9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXG4gICAgICAvcHJhZ21hXFxzK3NvbGlkaXR5XFxzK1xcXj8wXFwuWzAtN11cXC4vZ2lcbiAgICBdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5VbmNoZWNrZWRFeHRlcm5hbENhbGwsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ1VuY2hlY2tlZCBFeHRlcm5hbCBDYWxsJyxcbiAgICBkZXNjcmlwdGlvbjogJ0V4dGVybmFsIGNhbGwgcmV0dXJuIHZhbHVlIGlzIG5vdCBjaGVja2VkLCBtYXkgZmFpbCBzaWxlbnRseScsXG4gICAgcmVjb21tZW5kYXRpb246ICdBbHdheXMgY2hlY2sgdGhlIHJldHVybiB2YWx1ZSBvZiBsb3ctbGV2ZWwgY2FsbHMnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvXFwuY2FsbFxccypcXChbXildKlxcKVxccyo7L2dpLFxuICAgICAgL1xcLmRlbGVnYXRlY2FsbFxccypcXChbXildKlxcKVxccyo7L2dpLFxuICAgICAgL1xcLnN0YXRpY2NhbGxcXHMqXFwoW14pXSpcXClcXHMqOy9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuQWNjZXNzQ29udHJvbCxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuSGlnaCxcbiAgICBuYW1lOiAnTWlzc2luZyBBY2Nlc3MgQ29udHJvbCcsXG4gICAgZGVzY3JpcHRpb246ICdDcml0aWNhbCBmdW5jdGlvbiBsYWNrcyBwcm9wZXIgYWNjZXNzIGNvbnRyb2wgbW9kaWZpZXJzJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ0FkZCBhcHByb3ByaWF0ZSBhY2Nlc3MgY29udHJvbCBtb2RpZmllcnMgKG9ubHlPd25lciwgb25seUFkbWluLCBldGMuKScsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9mdW5jdGlvblxccytcXHcrXFxzKlxcKFteKV0qXFwpXFxzKig/OmV4dGVybmFsfHB1YmxpYylcXHMqKD86cHVyZXx2aWV3fHBheWFibGUpP1xccypcXHsvZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW1xuICAgICAgL29ubHlPd25lci9naSxcbiAgICAgIC9vbmx5QWRtaW4vZ2ksXG4gICAgICAvb25seVJvbGUvZ2ksXG4gICAgICAvbW9kaWZpZXJcXHMrb25seS9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlRpbWVzdGFtcERlcGVuZGVuY2UsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5Lk1lZGl1bSxcbiAgICBuYW1lOiAnVGltZXN0YW1wIERlcGVuZGVuY2UnLFxuICAgIGRlc2NyaXB0aW9uOiAnQ29udHJhY3QgbG9naWMgZGVwZW5kcyBvbiBibG9jay50aW1lc3RhbXAgd2hpY2ggbWluZXJzIGNhbiBtYW5pcHVsYXRlJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ0F2b2lkIHVzaW5nIGJsb2NrLnRpbWVzdGFtcCBmb3IgY3JpdGljYWwgbG9naWM7IHVzZSBibG9jay5udW1iZXIgd2hlbiBwb3NzaWJsZScsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9ibG9ja1xcLnRpbWVzdGFtcC9naSxcbiAgICAgIC9ub3dcXHMqKD8hXFxzKjopL2dpLFxuICAgICAgL2Jsb2NrXFwudGltZXN0YW1wXFxzKls8Pj0hXSsvZ2ksXG4gICAgICAvbm93XFxzKls8Pj0hXSsvZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW11cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkZyb250UnVubmluZyxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuTWVkaXVtLFxuICAgIG5hbWU6ICdGcm9udC1SdW5uaW5nIFZ1bG5lcmFiaWxpdHknLFxuICAgIGRlc2NyaXB0aW9uOiAnVHJhbnNhY3Rpb24gbWF5IGJlIHN1c2NlcHRpYmxlIHRvIGZyb250LXJ1bm5pbmcgYXR0YWNrcycsXG4gICAgcmVjb21tZW5kYXRpb246ICdVc2UgY29tbWl0LXJldmVhbCBzY2hlbWVzIG9yIGxpbWl0IHRyYW5zYWN0aW9uIGltcGFjdCcsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC90eFxcLm9yaWdpbi9naSxcbiAgICAgIC9ibG9ja1xcLm51bWJlclxccypbPD49IV0rL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5EZW5pYWxPZlNlcnZpY2UsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ1BvdGVudGlhbCBEb1MgVnVsbmVyYWJpbGl0eScsXG4gICAgZGVzY3JpcHRpb246ICdMb29wIG92ZXIgdW5ib3VuZGVkIGFycmF5IG1heSBjYXVzZSBnYXMgZXhoYXVzdGlvbicsXG4gICAgcmVjb21tZW5kYXRpb246ICdBdm9pZCB1bmJvdW5kZWQgbG9vcHM7IHVzZSBwdWxsLW92ZXItcHVzaCBwYXR0ZXJuJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2ZvclxccypcXChcXHMqKD86dWludHx1aW50MjU2KVxccytcXHcrXFxzKj1cXHMqMFxccyo7XFxzKlxcdytcXHMqPFxccypcXHcrXFwubGVuZ3RoL2dpLFxuICAgICAgL2ZvclxccypcXChcXHMqKD86dWludHx1aW50MjU2KVxccytcXHcrXFxzKzpcXHMrXFx3K1xccytpblxccysvZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW11cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkRnVuY3Rpb24sXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ1VucHJvdGVjdGVkIFNlbGYtRGVzdHJ1Y3QnLFxuICAgIGRlc2NyaXB0aW9uOiAnc2VsZmRlc3RydWN0IGNhbiBiZSBjYWxsZWQgYnkgYW55b25lIHdpdGhvdXQgYWNjZXNzIGNvbnRyb2wnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIGFjY2VzcyBjb250cm9sIG1vZGlmaWVyIHRvIHNlbGZkZXN0cnVjdCBjYWxscycsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9zZWxmZGVzdHJ1Y3RcXHMqXFwoL2dpLFxuICAgICAgL3N1aWNpZGVcXHMqXFwoL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9vbmx5T3duZXIvZ2ksXG4gICAgICAvb25seUFkbWluL2dpXG4gICAgXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuV2Vha1JhbmRvbW5lc3MsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ1dlYWsgUmFuZG9tbmVzcycsXG4gICAgZGVzY3JpcHRpb246ICdVc2luZyBibG9jayBwcm9wZXJ0aWVzIGZvciByYW5kb21uZXNzIGlzIHByZWRpY3RhYmxlIGFuZCBpbnNlY3VyZScsXG4gICAgcmVjb21tZW5kYXRpb246ICdVc2UgQ2hhaW5saW5rIFZSRiBvciBvdGhlciBzZWN1cmUgcmFuZG9tbmVzcyBzb3VyY2VzJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2Jsb2NraGFzaFxccypcXCgvZ2ksXG4gICAgICAvYmxvY2tcXC5kaWZmaWN1bHR5L2dpLFxuICAgICAgL2Jsb2NrXFwucHJldnJhbmRhby9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuRGVwcmVjYXRlZEZ1bmN0aW9uLFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5Mb3csXG4gICAgbmFtZTogJ0RlcHJlY2F0ZWQgRnVuY3Rpb24gVXNhZ2UnLFxuICAgIGRlc2NyaXB0aW9uOiAnVXNpbmcgZGVwcmVjYXRlZCBTb2xpZGl0eSBmdW5jdGlvbnMnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnVXBkYXRlIHRvIHVzZSByZWNvbW1lbmRlZCBhbHRlcm5hdGl2ZXMnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvc3VpY2lkZVxccypcXCgvZ2ksXG4gICAgICAvc2hhM1xccypcXCgvZ2ksXG4gICAgICAvdGhyb3dcXHMqOy9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuVW5pbml0aWFsaXplZFZhcmlhYmxlLFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgbmFtZTogJ1VuaW5pdGlhbGl6ZWQgU3RvcmFnZSBQb2ludGVyJyxcbiAgICBkZXNjcmlwdGlvbjogJ1N0b3JhZ2UgcG9pbnRlciBtYXkgYmUgdW5pbml0aWFsaXplZCwgbGVhZGluZyB0byB1bmV4cGVjdGVkIGJlaGF2aW9yJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ0V4cGxpY2l0bHkgaW5pdGlhbGl6ZSBzdG9yYWdlIHZhcmlhYmxlcyBvciB1c2UgbWVtb3J5IHdoZW4gYXBwcm9wcmlhdGUnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvc3RydWN0XFxzK1xcdytcXHMrXFx3K1xccyo7L2dpLFxuICAgICAgL2NvbnRyYWN0XFxzK1xcdytcXHMrXFx3K1xccyo7L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9tZW1vcnkvZ2ksXG4gICAgICAvc3RvcmFnZS9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkRlbGVnYXRlQ2FsbCxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuQ3JpdGljYWwsXG4gICAgbmFtZTogJ1Vuc2FmZSBEZWxlZ2F0ZWNhbGwnLFxuICAgIGRlc2NyaXB0aW9uOiAnZGVsZWdhdGVjYWxsIHRvIGFyYml0cmFyeSBhZGRyZXNzIGNhbiBsZWFkIHRvIGNvbnRyYWN0IHRha2VvdmVyJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ1Jlc3RyaWN0IGRlbGVnYXRlY2FsbCB0byB0cnVzdGVkIGFkZHJlc3NlcyBvbmx5OyBhdm9pZCB1c2luZyB3aXRoIHVzZXItY29udHJvbGxlZCBhZGRyZXNzZXMnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvZGVsZWdhdGVjYWxsXFxzKlxcKC9naSxcbiAgICAgIC9cXC5kZWxlZ2F0ZWNhbGxcXHMqXFwoL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5UeE9yaWdpbixcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuSGlnaCxcbiAgICBuYW1lOiAnVHggT3JpZ2luIEF1dGhlbnRpY2F0aW9uJyxcbiAgICBkZXNjcmlwdGlvbjogJ1VzaW5nIHR4Lm9yaWdpbiBmb3IgYXV0aGVudGljYXRpb24gaXMgdnVsbmVyYWJsZSB0byBwaGlzaGluZyBhdHRhY2tzJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBtc2cuc2VuZGVyIGluc3RlYWQgb2YgdHgub3JpZ2luIGZvciBhdXRoZW50aWNhdGlvbicsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC90eFxcLm9yaWdpblxccypbIT08Pj1dK1xccyovZ2ksXG4gICAgICAvcmVxdWlyZVxccypcXChcXHMqdHhcXC5vcmlnaW4vZ2ksXG4gICAgICAvaWZcXHMqXFwoXFxzKnR4XFwub3JpZ2luL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5CbG9ja2hhc2gsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsXG4gICAgbmFtZTogJ0Jsb2NraGFzaCBVc2FnZScsXG4gICAgZGVzY3JpcHRpb246ICdVc2luZyBibG9ja2hhc2ggZm9yIHJhbmRvbW5lc3Mgb3Igc2VjdXJpdHkgaXMgcHJlZGljdGFibGUnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnVXNlIENoYWlubGluayBWUkYgb3Igb3RoZXIgc2VjdXJlIHJhbmRvbW5lc3Mgc291cmNlcycsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9ibG9ja1xcLmJsb2NraGFzaFxccypcXCgvZ2ksXG4gICAgICAvYmxvY2toYXNoXFxzKlxcKC9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuU2lnbmF0dXJlTWFsbGVhYmlsaXR5LFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5IaWdoLFxuICAgIG5hbWU6ICdTaWduYXR1cmUgTWFsbGVhYmlsaXR5JyxcbiAgICBkZXNjcmlwdGlvbjogJ0VDRFNBIHNpZ25hdHVyZSBtYXkgYmUgbWFsbGVhYmxlLCBhbGxvd2luZyByZXBsYXkgYXR0YWNrcycsXG4gICAgcmVjb21tZW5kYXRpb246ICdVc2UgT3BlblplcHBlbGluIEVDRFNBIGxpYnJhcnkgd2l0aCBwcm9wZXIgc2lnbmF0dXJlIHZhbGlkYXRpb24nLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvZWNyZWNvdmVyXFxzKlxcKC9naSxcbiAgICAgIC9zcGxpdFNpZ25hdHVyZVxccypcXCgvZ2ksXG4gICAgICAvXFwuclxccyosXFxzKlxcLnNcXHMqLFxccypcXC52L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5TaG9ydEFkZHJlc3MsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5Lk1lZGl1bSxcbiAgICBuYW1lOiAnU2hvcnQgQWRkcmVzcyBBdHRhY2snLFxuICAgIGRlc2NyaXB0aW9uOiAnQ29udHJhY3QgbWF5IGJlIHZ1bG5lcmFibGUgdG8gc2hvcnQgYWRkcmVzcyBhdHRhY2sgaW4gdG9rZW4gdHJhbnNmZXJzJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ1ZhbGlkYXRlIGFkZHJlc3MgbGVuZ3RoIGJlZm9yZSB0cmFuc2ZlciBvcGVyYXRpb25zJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL3RyYW5zZmVyXFxzKlxcKFxccyphZGRyZXNzL2dpLFxuICAgICAgL3RyYW5zZmVyRnJvbVxccypcXChbXildKmFkZHJlc3MvZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW11cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkhpZGRlbk93bmVyLFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5IaWdoLFxuICAgIG5hbWU6ICdIaWRkZW4gT3duZXIgUGF0dGVybicsXG4gICAgZGVzY3JpcHRpb246ICdDb250cmFjdCBtYXkgaGF2ZSBoaWRkZW4gb3duZXIgZnVuY3Rpb25hbGl0eSB0aGF0IGNhbiBiZSBleHBsb2l0ZWQnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnUmV2aWV3IGNvbnRyYWN0IGZvciBoaWRkZW4gYWRtaW5pc3RyYXRpdmUgZnVuY3Rpb25zJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL293bmVyXFxzKj1cXHMqdHhcXC5vcmlnaW4vZ2ksXG4gICAgICAvb3duZXJcXHMqPVxccyptc2dcXC5zZW5kZXIvZ2ksXG4gICAgICAvX293bmVyXFxzKj0vZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW11cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkhhcmRjb2RlZEFkZHJlc3MsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5Lk1lZGl1bSxcbiAgICBuYW1lOiAnSGFyZGNvZGVkIEFkZHJlc3MnLFxuICAgIGRlc2NyaXB0aW9uOiAnSGFyZGNvZGVkIGFkZHJlc3NlcyBtYXkgaW5kaWNhdGUgYmFja2Rvb3JzIG9yIHJlZHVjZSBmbGV4aWJpbGl0eScsXG4gICAgcmVjb21tZW5kYXRpb246ICdVc2UgY29uZmlndXJhYmxlIGFkZHJlc3NlcyBvciBjb25zdGFudHMgd2l0aCBjbGVhciBkb2N1bWVudGF0aW9uJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgLzB4WzAtOWEtZkEtRl17NDB9L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9jb25zdGFudC9naSxcbiAgICAgIC9pbW11dGFibGUvZ2lcbiAgICBdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5NaXNzaW5nWmVyb0NoZWNrLFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgbmFtZTogJ01pc3NpbmcgWmVybyBBZGRyZXNzIENoZWNrJyxcbiAgICBkZXNjcmlwdGlvbjogJ0Z1bmN0aW9uIGRvZXMgbm90IHZhbGlkYXRlIGFnYWluc3QgemVybyBhZGRyZXNzJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ0FkZCB6ZXJvIGFkZHJlc3MgdmFsaWRhdGlvbiBmb3IgY3JpdGljYWwgYWRkcmVzcyBwYXJhbWV0ZXJzJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2Z1bmN0aW9uXFxzK1xcdytcXHMqXFwoW14pXSphZGRyZXNzXFxzK1xcdytbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC8hPVxccyphZGRyZXNzXFxzKlxcKFxccyowXFxzKlxcKS9naSxcbiAgICAgIC8hPVxccyphZGRyZXNzMC9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVuc2FmZUVSQzIwLFxuICAgIHNldmVyaXR5OiBTZXZlcml0eS5NZWRpdW0sXG4gICAgbmFtZTogJ1Vuc2FmZSBFUkMyMCBPcGVyYXRpb25zJyxcbiAgICBkZXNjcmlwdGlvbjogJ1VzaW5nIHRyYW5zZmVyL3RyYW5zZmVyRnJvbSB3aXRob3V0IGhhbmRsaW5nIG5vbi1zdGFuZGFyZCB0b2tlbnMnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnVXNlIFNhZmVFUkMyMCBsaWJyYXJ5IGZvciB0b2tlbiBvcGVyYXRpb25zJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL0lFUkMyMFxccypcXChbXildK1xcKVxcLnRyYW5zZmVyXFxzKlxcKC9naSxcbiAgICAgIC9JRVJDMjBcXHMqXFwoW14pXStcXClcXC50cmFuc2ZlckZyb21cXHMqXFwoL2dpLFxuICAgICAgL3Rva2VuXFwudHJhbnNmZXJcXHMqXFwoL2dpLFxuICAgICAgL3Rva2VuXFwudHJhbnNmZXJGcm9tXFxzKlxcKC9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXG4gICAgICAvU2FmZUVSQzIwL2dpLFxuICAgICAgL3VzaW5nXFxzK1NhZmVFUkMyMC9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLk1pc3NpbmdFdmVudCxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuTG93LFxuICAgIG5hbWU6ICdNaXNzaW5nIEV2ZW50IEVtaXNzaW9uJyxcbiAgICBkZXNjcmlwdGlvbjogJ0NyaXRpY2FsIHN0YXRlIGNoYW5nZXMgc2hvdWxkIGVtaXQgZXZlbnRzIGZvciBvZmYtY2hhaW4gdHJhY2tpbmcnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIGV2ZW50IGVtaXNzaW9ucyBmb3IgaW1wb3J0YW50IHN0YXRlIGNoYW5nZXMnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvZnVuY3Rpb25cXHMrXFx3K1xccypcXChbXildKlxcKVxccyooPzpleHRlcm5hbHxwdWJsaWMpXFxzKig/Om92ZXJyaWRlKT9cXHMqXFx7W159XSpcXH0vZ2lcbiAgICBdLFxuICAgIGNvbnRleHRQYXR0ZXJuczogW1xuICAgICAgL2VtaXRcXHMrXFx3Ky9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkSW5pdGlhbGl6ZSxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuQ3JpdGljYWwsXG4gICAgbmFtZTogJ1VucHJvdGVjdGVkIEluaXRpYWxpemUgRnVuY3Rpb24nLFxuICAgIGRlc2NyaXB0aW9uOiAnSW5pdGlhbGl6ZSBmdW5jdGlvbiBsYWNrcyBhY2Nlc3MgY29udHJvbCwgYWxsb3dpbmcgYW55b25lIHRvIGluaXRpYWxpemUnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIG9ubHlJbml0aWFsaXppbmcgb3Igc2ltaWxhciBtb2RpZmllciB0byBpbml0aWFsaXplIGZ1bmN0aW9ucycsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9mdW5jdGlvblxccytpbml0aWFsaXplXFxzKlxcKC9naSxcbiAgICAgIC9mdW5jdGlvblxccytpbml0XFxzKlxcKC9naSxcbiAgICAgIC9mdW5jdGlvblxccytpbml0aWFsaXplVjJcXHMqXFwoL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9vbmx5SW5pdGlhbGl6aW5nL2dpLFxuICAgICAgL29ubHlQcm94eS9naSxcbiAgICAgIC9pbml0aWFsaXplci9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkNlbnRyYWxpemF0aW9uUmlzayxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuTWVkaXVtLFxuICAgIG5hbWU6ICdDZW50cmFsaXphdGlvbiBSaXNrJyxcbiAgICBkZXNjcmlwdGlvbjogJ0NvbnRyYWN0IGhhcyBzaW5nbGUgcG9pbnQgb2YgY29udHJvbCB0aGF0IGNyZWF0ZXMgY2VudHJhbGl6YXRpb24gcmlzaycsXG4gICAgcmVjb21tZW5kYXRpb246ICdDb25zaWRlciBtdWx0aS1zaWcgb3IgREFPIGdvdmVybmFuY2UgZm9yIGNyaXRpY2FsIGZ1bmN0aW9ucycsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9vbmx5T3duZXJcXHMqKD86ZXh0ZXJuYWx8cHVibGljKS9naSxcbiAgICAgIC9mdW5jdGlvblxccytcXHcrXFxzKlxcKFteKV0qXFwpXFxzKm9ubHlPd25lci9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuTWlzc2luZ0lucHV0VmFsaWRhdGlvbixcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuTWVkaXVtLFxuICAgIG5hbWU6ICdNaXNzaW5nIElucHV0IFZhbGlkYXRpb24nLFxuICAgIGRlc2NyaXB0aW9uOiAnRnVuY3Rpb24gcGFyYW1ldGVycyBhcmUgbm90IHByb3Blcmx5IHZhbGlkYXRlZCcsXG4gICAgcmVjb21tZW5kYXRpb246ICdBZGQgcmVxdWlyZSBzdGF0ZW1lbnRzIHRvIHZhbGlkYXRlIGFsbCBpbnB1dCBwYXJhbWV0ZXJzJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2Z1bmN0aW9uXFxzK1xcdytcXHMqXFwoW14pXSp1aW50W14pXSpcXClcXHMqKD86ZXh0ZXJuYWx8cHVibGljKVxccypcXHtbXn1dKlxcfS9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXG4gICAgICAvcmVxdWlyZVxccypcXCgvZ2ksXG4gICAgICAvaWZcXHMqXFwoW14pXSo8PS9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLlVuc2FmZUNhc3QsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5Lk1lZGl1bSxcbiAgICBuYW1lOiAnVW5zYWZlIFR5cGUgQ2FzdGluZycsXG4gICAgZGVzY3JpcHRpb246ICdUeXBlIGNhc3RpbmcgbWF5IHRydW5jYXRlIGRhdGEgb3IgY2F1c2UgdW5leHBlY3RlZCBiZWhhdmlvcicsXG4gICAgcmVjb21tZW5kYXRpb246ICdFbnN1cmUgdHlwZSBjYXN0cyBhcmUgc2FmZSBhbmQgZG8gbm90IGxvc2UgZGF0YScsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC91aW50XFxkKlxccypcXChcXHMqdWludFxcZCtcXHMqXFwpL2dpLFxuICAgICAgL2ludFxcZCpcXHMqXFwoXFxzKmludFxcZCtcXHMqXFwpL2dpLFxuICAgICAgL2FkZHJlc3NcXHMqXFwoXFxzKnVpbnQvZ2ksXG4gICAgICAvdWludFxccypcXChcXHMqaW50L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5TaGFkb3dpbmcsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkxvdyxcbiAgICBuYW1lOiAnVmFyaWFibGUgU2hhZG93aW5nJyxcbiAgICBkZXNjcmlwdGlvbjogJ0xvY2FsIHZhcmlhYmxlIHNoYWRvd3Mgc3RhdGUgdmFyaWFibGUgb3IgZnVuY3Rpb24gcGFyYW1ldGVyJyxcbiAgICByZWNvbW1lbmRhdGlvbjogJ1VzZSBkaWZmZXJlbnQgbmFtZXMgZm9yIGxvY2FsIHZhcmlhYmxlcyB0byBhdm9pZCBzaGFkb3dpbmcnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvZnVuY3Rpb25cXHMrXFx3K1xccypcXChbXildKihcXHcrKVxccytcXHcrW14pXSpcXClbXntdKlxce1tefV0qXFxiXFwxXFxiL2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5Db25zdGFuY3lJc3N1ZXMsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkxvdyxcbiAgICBuYW1lOiAnQ29uc3RhbmN5IElzc3VlcycsXG4gICAgZGVzY3JpcHRpb246ICdGdW5jdGlvbiBzaG91bGQgYmUgZGVjbGFyZWQgcHVyZSBvciB2aWV3IGJ1dCBpcyBub3QnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIHB1cmUgb3IgdmlldyBtb2RpZmllciB0byBmdW5jdGlvbnMgdGhhdCBkbyBub3QgbW9kaWZ5IHN0YXRlJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2Z1bmN0aW9uXFxzK1xcdytcXHMqXFwoW14pXSpcXClcXHMqKD86ZXh0ZXJuYWx8cHVibGljKVxccyooPyFwdXJlfHZpZXcpXFx7W159XSpyZXR1cm5bXn1dKlxcfS9naVxuICAgIF0sXG4gICAgY29udGV4dFBhdHRlcm5zOiBbXG4gICAgICAvc3RhdGVWYXJpYWJsZVxccyo9L2dpLFxuICAgICAgL2VtaXRcXHMrL2dpXG4gICAgXVxuICB9LFxuICB7XG4gICAgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuSW5jb3JyZWN0TW9kaWZpZXIsXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5Lk1lZGl1bSxcbiAgICBuYW1lOiAnSW5jb3JyZWN0IE1vZGlmaWVyIFVzYWdlJyxcbiAgICBkZXNjcmlwdGlvbjogJ01vZGlmaWVyIG1heSBoYXZlIGxvZ2ljIGVycm9ycyBvciBiZSBpbmNvcnJlY3RseSBpbXBsZW1lbnRlZCcsXG4gICAgcmVjb21tZW5kYXRpb246ICdSZXZpZXcgbW9kaWZpZXIgbG9naWMgZm9yIGNvcnJlY3RuZXNzIGFuZCBzZWN1cml0eScsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9tb2RpZmllclxccytcXHcrXFxzKlxcKFteKV0qXFwpXFxzKlxce1tefV0qX1tefV0qXFx9L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5NaXNzaW5nRmFsbGJhY2ssXG4gICAgc2V2ZXJpdHk6IFNldmVyaXR5LkxvdyxcbiAgICBuYW1lOiAnTWlzc2luZyBGYWxsYmFjayBGdW5jdGlvbicsXG4gICAgZGVzY3JpcHRpb246ICdDb250cmFjdCBtYXkgbmVlZCBhIGZhbGxiYWNrL3JlY2VpdmUgZnVuY3Rpb24gdG8gaGFuZGxlIGRpcmVjdCB0cmFuc2ZlcnMnLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnQWRkIHJlY2VpdmUoKSBvciBmYWxsYmFjaygpIGZ1bmN0aW9uIGlmIGNvbnRyYWN0IHNob3VsZCBhY2NlcHQgRVRIJyxcbiAgICBwYXR0ZXJuczogW1xuICAgICAgL2NvbnRyYWN0XFxzK1xcdytbXntdKlxce1tefV0qcGF5YWJsZVtefV0qXFx9L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9yZWNlaXZlXFxzKlxcKFxccypcXCkvZ2ksXG4gICAgICAvZmFsbGJhY2tcXHMqXFwoXFxzKlxcKS9naVxuICAgIF1cbiAgfSxcbiAge1xuICAgIHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkV0aGVyTG9zcyxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuQ3JpdGljYWwsXG4gICAgbmFtZTogJ1BvdGVudGlhbCBFdGhlciBMb3NzJyxcbiAgICBkZXNjcmlwdGlvbjogJ0NvbnRyYWN0IG1heSB0cmFwIG9yIGxvc2UgRXRoZXIgZHVlIHRvIGltcGxlbWVudGF0aW9uIGlzc3VlcycsXG4gICAgcmVjb21tZW5kYXRpb246ICdSZXZpZXcgY29udHJhY3QgZm9yIHBvdGVudGlhbCBFdGhlciB0cmFwcGluZyBzY2VuYXJpb3MnLFxuICAgIHBhdHRlcm5zOiBbXG4gICAgICAvYWRkcmVzc1xccypcXChbXildK1xcKVxcLmJhbGFuY2VcXHMqPS9naSxcbiAgICAgIC9iYWxhbmNlXFxzKj1cXHMqMFxccyo7L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtdXG4gIH0sXG4gIHtcbiAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5Jbmhlcml0YW5jZUlzc3VlcyxcbiAgICBzZXZlcml0eTogU2V2ZXJpdHkuTWVkaXVtLFxuICAgIG5hbWU6ICdJbmhlcml0YW5jZSBPcmRlciBJc3N1ZXMnLFxuICAgIGRlc2NyaXB0aW9uOiAnQ29udHJhY3QgaW5oZXJpdGFuY2Ugb3JkZXIgbWF5IGNhdXNlIHVuZXhwZWN0ZWQgYmVoYXZpb3InLFxuICAgIHJlY29tbWVuZGF0aW9uOiAnUmV2aWV3IGluaGVyaXRhbmNlIG9yZGVyIGZvciBwcm9wZXIgZnVuY3Rpb24gb3ZlcnJpZGluZycsXG4gICAgcGF0dGVybnM6IFtcbiAgICAgIC9jb250cmFjdFxccytcXHcrXFxzK2lzXFxzK1tee10rXFx7L2dpXG4gICAgXSxcbiAgICBjb250ZXh0UGF0dGVybnM6IFtcbiAgICAgIC9vdmVycmlkZS9naVxuICAgIF1cbiAgfVxuXTtcblxuZXhwb3J0IGZ1bmN0aW9uIGdldFBhdHRlcm5CeVR5cGUodHlwZTogVnVsbmVyYWJpbGl0eVR5cGUpOiBWdWxuZXJhYmlsaXR5UGF0dGVybiB8IHVuZGVmaW5lZCB7XG4gIHJldHVybiBWVUxORVJBQklMSVRZX1BBVFRFUk5TLmZpbmQocCA9PiBwLnR5cGUgPT09IHR5cGUpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0UGF0dGVybnNCeVNldmVyaXR5KHNldmVyaXR5OiBTZXZlcml0eSk6IFZ1bG5lcmFiaWxpdHlQYXR0ZXJuW10ge1xuICByZXR1cm4gVlVMTkVSQUJJTElUWV9QQVRURVJOUy5maWx0ZXIocCA9PiBwLnNldmVyaXR5ID09PSBzZXZlcml0eSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRBbGxWdWxuZXJhYmlsaXR5VHlwZXMoKTogVnVsbmVyYWJpbGl0eVR5cGVbXSB7XG4gIHJldHVybiBPYmplY3QudmFsdWVzKFZ1bG5lcmFiaWxpdHlUeXBlKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldEFsbFNldmVyaXR5TGV2ZWxzKCk6IFNldmVyaXR5W10ge1xuICByZXR1cm4gT2JqZWN0LnZhbHVlcyhTZXZlcml0eSk7XG59XG4iXX0=