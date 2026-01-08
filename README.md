# Smart Contract Security Auditor

A TypeScript-based security analyzer for detecting vulnerabilities in Solidity smart contracts. This tool performs static analysis on Solidity code to identify common security issues and best practice violations.

## Features

- **Pattern-based Detection**: Identifies 40+ common vulnerability types
- **Severity Classification**: Issues categorized as Critical, High, Medium, Low, or Info
- **Context-Aware Analysis**: Considers surrounding code context for accurate detection
- **Multiple Output Formats**: Console output with colors or JSON format
- **Configurable Scanning**: Filter by severity, exclude specific vulnerability types
- **Directory Scanning**: Analyze single files or entire directories recursively

## Supported Vulnerability Types

### Critical Severity

| Type | Description |
|------|-------------|
| `reentrancy` | External calls before state updates enabling reentrancy attacks |
| `delegatecall` | Unsafe delegatecall to arbitrary addresses |
| `unprotected_initialize` | Initialize function lacks access control |
| `ether_loss` | Code may trap or lose Ether |

### High Severity

| Type | Description |
|------|-------------|
| `integer_overflow` | Arithmetic overflow without SafeMath checks |
| `integer_underflow` | Arithmetic underflow without SafeMath checks |
| `unchecked_external_call` | Unchecked low-level call return values |
| `access_control` | Missing access control on critical functions |
| `denial_of_service` | Unbounded loops causing gas exhaustion |
| `unprotected_function` | Self-destruct without access control |
| `weak_randomness` | Using block properties for randomness |
| `tx_origin` | Using tx.origin for authentication |
| `blockhash` | Using blockhash for randomness or security |
| `signature_malleability` | ECDSA signature malleability issues |
| `hidden_owner` | Hidden owner functionality |

### Medium Severity

| Type | Description |
|------|-------------|
| `timestamp_dependence` | Logic depends on manipulable timestamps |
| `front_running` | Transactions susceptible to front-running |
| `uninitialized_variable` | Uninitialized storage pointers |
| `short_address` | Vulnerable to short address attack |
| `hardcoded_address` | Hardcoded addresses without documentation |
| `missing_zero_check` | Missing zero address validation |
| `unsafe_erc20` | Unsafe ERC20 transfer operations |
| `centralization_risk` | Single point of control |
| `missing_input_validation` | Function parameters not validated |
| `unsafe_cast` | Unsafe type casting |
| `incorrect_modifier` | Modifier logic errors |
| `inheritance_issues` | Inheritance order problems |

### Low Severity

| Type | Description |
|------|-------------|
| `deprecated_function` | Use of deprecated Solidity functions |
| `missing_event` | Missing event emissions for state changes |
| `shadowing` | Variable shadowing state variables |
| `constancy_issues` | Functions should be pure or view |
| `missing_fallback` | Missing fallback/receive function |

## Installation

```bash
# Clone or download the project
cd smart-contract-auditor

# Install dependencies
npm install

# Build the project
npm run build
```

## Usage

### Command Line

```bash
# Analyze a single file
npx ts-node src/index.ts ./contracts/MyToken.sol

# Analyze a directory recursively
npx ts-node src/index.ts ./contracts/ -r

# Filter by minimum severity
npx ts-node src/index.ts ./contracts/ -s high

# Exclude specific vulnerability types
npx ts-node src/index.ts ./contracts/ --exclude reentrancy --exclude timestamp_dependence

# Output results as JSON
npx ts-node src/index.ts ./contracts/ --json

# Save results to a file
npx ts-node src/index.ts ./contracts/ -o report.txt

# Show help
npx ts-node src/index.ts --help
```

### Programmatic Usage

```typescript
import { createAnalyzer, analyzeContracts } from './src/analyzer';
import { VulnerabilityType, Severity } from './src/patterns';

// Create analyzer with options
const analyzer = createAnalyzer({
  excludePatterns: [VulnerabilityType.Reentrancy],
  includeWarnings: true
});

// Analyze a single file
const result = analyzer.analyzeFile('./contracts/MyContract.sol');
console.log(`Found ${result.results.length} issues`);

// Analyze multiple files
const report = analyzer.analyzeFiles([
  './contracts/Token.sol',
  './contracts/Vault.sol'
]);
console.log(`Total issues: ${report.totalIssues}`);

// Use convenience function
const analysis = analyzeContracts(['./contracts/']);
```

### Adding Custom Patterns

```typescript
import { createAnalyzer } from './src/analyzer';
import { VulnerabilityType, Severity } from './src/patterns';

const analyzer = createAnalyzer();

// Add a custom vulnerability pattern
analyzer.addCustomPattern({
  type: VulnerabilityType.DeprecatedFunction,
  severity: Severity.Low,
  name: 'Custom Pattern',
  description: 'Detects custom pattern',
  recommendation: 'Fix the issue',
  patterns: [/custom_regex_pattern/gi]
});
```

## How It Works

### Analysis Process

1. **File Parsing**: Reads Solidity source files and splits into lines
2. **Pattern Matching**: Applies regex patterns to detect potential vulnerabilities
3. **Context Analysis**: Examines surrounding code for additional context
4. **Issue Classification**: Assigns severity based on vulnerability type
5. **Deduplication**: Removes duplicate findings
6. **Reporting**: Formats and outputs results

### Detection Methods

The analyzer uses several detection strategies:

- **Direct Pattern Matching**: Regex patterns match known vulnerability signatures
- **Contextual Analysis**: Considers nearby code (e.g., access control modifiers)
- **Flow Analysis**: Tracks state changes and external calls within functions
- **Structural Analysis**: Examines contract structure for missing protections

### Example Analysis

For a contract with reentrancy vulnerability:

```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // External call
    balances[msg.sender] -= amount;  // State update AFTER call
}
```

The analyzer detects:
- External call (`call`) before state update
- Missing checks-effects-interactions pattern
- Reports as Critical severity reentrancy vulnerability

## Project Structure

```
smart-contract-auditor/
├── src/
│   ├── index.ts         # Main entry point and CLI
│   ├── analyzer.ts      # Core analysis logic
│   ├── patterns.ts      # Vulnerability pattern definitions
│   └── utils.ts         # Helper utilities
├── tests/
│   └── analyzer.test.ts # Unit tests
├── package.json
├── tsconfig.json
└── README.md
```

## Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage (if configured)
npm test -- --coverage
```

## Configuration

### Severity Levels

- **Critical**: Issues that can lead to complete loss of funds
- **High**: Significant security issues requiring immediate attention
- **Medium**: Moderate security concerns that should be addressed
- **Low**: Minor issues or best practice violations
- **Info**: Informational findings for awareness

### Risk Score

The analyzer calculates a risk score (0-100) based on:
- Number of issues at each severity level
- Weighted scoring: Critical=10, High=5, Medium=3, Low=1, Info=0

Risk levels:
- 80-100: CRITICAL
- 50-79: HIGH
- 30-49: MEDIUM
- 10-29: LOW
- 0-9: MINIMAL

## New Vulnerability Patterns

The following vulnerability patterns have been added:

### DelegateCall Detection
Detects unsafe usage of delegatecall which can lead to contract takeover if the target address is user-controlled.

### TxOrigin Authentication
Identifies use of tx.origin for authentication, which is vulnerable to phishing attacks.

### Signature Malleability
Detects direct use of ecrecover without proper signature validation, vulnerable to malleability attacks.

### Hardcoded Address
Finds hardcoded addresses that may indicate backdoors or reduce contract flexibility.

### Missing Zero Check
Identifies functions that accept address parameters without validating against zero address.

### Unsafe ERC20 Operations
Detects direct use of transfer/transferFrom without SafeERC20 library for non-standard token handling.

### Unprotected Initialize
Finds initialize functions in upgradeable contracts that lack proper access control modifiers.

### Unsafe Type Cast
Identifies potentially unsafe type conversions that may truncate data.

### Variable Shadowing
Detects local variables or parameters that shadow state variables.

### Missing Fallback
Identifies contracts with payable functions but no fallback/receive function.

### Ether Loss
Detects patterns that may trap or lose Ether.

### Inheritance Issues
Identifies potential problems with contract inheritance order.

## Limitations

- Static analysis only; does not execute code
- May produce false positives
- Does not replace manual security audits
- Pattern-based detection may miss novel vulnerabilities
- Best used as part of a comprehensive security review process

## License

MIT
