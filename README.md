# Smart Contract Security Auditor

A TypeScript-based security analyzer for detecting vulnerabilities in Solidity smart contracts. This tool performs static analysis on Solidity code to identify common security issues and best practice violations.

## Features

- **Pattern-based Detection**: Identifies 12+ common vulnerability types
- **Severity Classification**: Issues categorized as Critical, High, Medium, Low, or Info
- **Context-Aware Analysis**: Considers surrounding code context for accurate detection
- **Multiple Output Formats**: Console output with colors or JSON format
- **Configurable Scanning**: Filter by severity, exclude specific vulnerability types
- **Directory Scanning**: Analyze single files or entire directories recursively

## Supported Vulnerability Types

| Type | Severity | Description |
|------|----------|-------------|
| `reentrancy` | Critical | External calls before state updates |
| `integer_overflow` | High | Arithmetic overflow without checks |
| `integer_underflow` | High | Arithmetic underflow without checks |
| `unchecked_external_call` | High | Unchecked low-level call return values |
| `access_control` | High | Missing access control on critical functions |
| `denial_of_service` | High | Unbounded loops causing gas exhaustion |
| `unprotected_function` | High | Self-destruct without access control |
| `weak_randomness` | High | Using block properties for randomness |
| `timestamp_dependence` | Medium | Logic depends on manipulable timestamps |
| `front_running` | Medium | Transactions susceptible to front-running |
| `uninitialized_variable` | Medium | Uninitialized storage pointers |
| `deprecated_function` | Low | Use of deprecated Solidity functions |

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

## Limitations

- Static analysis only; does not execute code
- May produce false positives
- Does not replace manual security audits
- Pattern-based detection may miss novel vulnerabilities
- Best used as part of a comprehensive security review process

## License

MIT
