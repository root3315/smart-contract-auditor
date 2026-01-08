/**
 * Unit tests for the Smart Contract Security Analyzer.
 */

import {
  SmartContractAnalyzer,
  createAnalyzer,
  analyzeContracts,
  AnalyzerOptions
} from '../src/analyzer';
import {
  VulnerabilityType,
  Severity,
  VULNERABILITY_PATTERNS,
  getPatternByType,
  getPatternsBySeverity
} from '../src/patterns';
import {
  readSolidityFile,
  extractLine,
  getSurroundingLines,
  formatSeverity,
  generateSummary,
  isCommentLine,
  getContractName,
  getPragmaVersion,
  normalizeWhitespace,
  filterComments,
  findStateVariables,
  findFunctions,
  findEvents,
  findModifiers,
  countLines,
  getInheritanceChain,
  isUpgradeable
} from '../src/utils';
import * as fs from 'fs';
import * as path from 'path';

describe('Vulnerability Patterns', () => {
  describe('getPatternByType', () => {
    it('should return pattern for reentrancy', () => {
      const pattern = getPatternByType(VulnerabilityType.Reentrancy);
      expect(pattern).toBeDefined();
      expect(pattern?.type).toBe(VulnerabilityType.Reentrancy);
      expect(pattern?.severity).toBe(Severity.Critical);
    });

    it('should return pattern for integer overflow', () => {
      const pattern = getPatternByType(VulnerabilityType.IntegerOverflow);
      expect(pattern).toBeDefined();
      expect(pattern?.severity).toBe(Severity.High);
    });

    it('should return pattern for delegatecall', () => {
      const pattern = getPatternByType(VulnerabilityType.DelegateCall);
      expect(pattern).toBeDefined();
      expect(pattern?.severity).toBe(Severity.Critical);
    });

    it('should return pattern for tx origin', () => {
      const pattern = getPatternByType(VulnerabilityType.TxOrigin);
      expect(pattern).toBeDefined();
      expect(pattern?.severity).toBe(Severity.High);
    });

    it('should return pattern for signature malleability', () => {
      const pattern = getPatternByType(VulnerabilityType.SignatureMalleability);
      expect(pattern).toBeDefined();
      expect(pattern?.severity).toBe(Severity.High);
    });

    it('should return undefined for non-existent type', () => {
      const pattern = getPatternByType(('nonexistent' as unknown) as VulnerabilityType);
      expect(pattern).toBeUndefined();
    });
  });

  describe('getPatternsBySeverity', () => {
    it('should return all critical patterns', () => {
      const patterns = getPatternsBySeverity(Severity.Critical);
      expect(patterns.length).toBeGreaterThan(0);
      patterns.forEach(p => expect(p.severity).toBe(Severity.Critical));
    });

    it('should return all high severity patterns', () => {
      const patterns = getPatternsBySeverity(Severity.High);
      expect(patterns.length).toBeGreaterThan(0);
      patterns.forEach(p => expect(p.severity).toBe(Severity.High));
    });
  });

  describe('VULNERABILITY_PATTERNS', () => {
    it('should have all required fields', () => {
      VULNERABILITY_PATTERNS.forEach(pattern => {
        expect(pattern.type).toBeDefined();
        expect(pattern.severity).toBeDefined();
        expect(pattern.name).toBeDefined();
        expect(pattern.description).toBeDefined();
        expect(pattern.recommendation).toBeDefined();
        expect(pattern.patterns).toBeDefined();
        expect(pattern.patterns.length).toBeGreaterThan(0);
      });
    });

    it('should include new vulnerability types', () => {
      const newTypes = [
        VulnerabilityType.DelegateCall,
        VulnerabilityType.TxOrigin,
        VulnerabilityType.SignatureMalleability,
        VulnerabilityType.HardcodedAddress,
        VulnerabilityType.MissingZeroCheck,
        VulnerabilityType.UnsafeERC20,
        VulnerabilityType.UnprotectedInitialize,
        VulnerabilityType.UnsafeCast,
        VulnerabilityType.Shadowing
      ];

      newTypes.forEach(type => {
        const pattern = getPatternByType(type);
        expect(pattern).toBeDefined();
      });
    });
  });
});

describe('SmartContractAnalyzer', () => {
  let analyzer: SmartContractAnalyzer;
  let testContractPath: string;

  beforeAll(() => {
    analyzer = createAnalyzer();

    const testContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract VulneribleContract {
    mapping(address => uint) balances;
    uint totalSupply;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }

    function getRandom() external view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    function processUsers(address[] memory users) external {
        for (uint i = 0; i < users.length; i++) {
            require(users[i] != address(0));
        }
    }
}
`;

    testContractPath = path.join(__dirname, 'test-contract.sol');
    fs.writeFileSync(testContractPath, testContract);
  });

  afterAll(() => {
    if (fs.existsSync(testContractPath)) {
      fs.unlinkSync(testContractPath);
    }
  });

  describe('constructor', () => {
    it('should create analyzer with default options', () => {
      const defaultAnalyzer = createAnalyzer();
      expect(defaultAnalyzer).toBeInstanceOf(SmartContractAnalyzer);
    });

    it('should create analyzer with custom options', () => {
      const options: AnalyzerOptions = {
        excludePatterns: [VulnerabilityType.Reentrancy],
        includeWarnings: false
      };
      const customAnalyzer = createAnalyzer(options);
      expect(customAnalyzer).toBeInstanceOf(SmartContractAnalyzer);
    });
  });

  describe('analyzeFile', () => {
    it('should analyze a Solidity file and return results', () => {
      const result = analyzer.analyzeFile(testContractPath);

      expect(result.file).toBe(testContractPath);
      expect(result.contractName).toBe('VulneribleContract');
      expect(result.pragmaVersion).toBe('^0.7.0');
      expect(result.linesAnalyzed).toBeGreaterThan(0);
      expect(result.results.length).toBeGreaterThan(0);
    });

    it('should detect reentrancy vulnerability', () => {
      const testContract = `
pragma solidity ^0.7.0;

contract ReentrancyTest {
    mapping(address => uint) balances;

    function withdraw(uint amount) external {
        owner = msg.sender;
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
`;
      const testPath = path.join(__dirname, 'reentrancy-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const result = analyzer.analyzeFile(testPath);
        expect(result.results.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });

    it('should detect timestamp dependence', () => {
      const result = analyzer.analyzeFile(testContractPath);
      const timestampIssues = result.results.filter(
        r => r.type === VulnerabilityType.TimestampDependence
      );
      expect(timestampIssues.length).toBeGreaterThan(0);
    });

    it('should detect weak randomness', () => {
      const result = analyzer.analyzeFile(testContractPath);
      const randomnessIssues = result.results.filter(
        r => r.type === VulnerabilityType.WeakRandomness
      );
      expect(randomnessIssues.length).toBeGreaterThan(0);
    });

    it('should detect DoS vulnerability', () => {
      const result = analyzer.analyzeFile(testContractPath);
      const dosIssues = result.results.filter(
        r => r.type === VulnerabilityType.DenialOfService
      );
      expect(dosIssues.length).toBeGreaterThan(0);
    });
  });

  describe('analyzeFiles', () => {
    it('should analyze multiple files', () => {
      const report = analyzer.analyzeFiles([testContractPath]);

      expect(report.files.length).toBe(1);
      expect(report.totalIssues).toBeGreaterThan(0);
      expect(report.timestamp).toBeDefined();
    });

    it('should handle non-existent files gracefully', () => {
      const report = analyzer.analyzeFiles(['/nonexistent/file.sol']);

      expect(report.files.length).toBe(1);
      expect(report.files[0].results.length).toBe(0);
    });
  });

  describe('pattern management', () => {
    it('should add custom patterns', () => {
      const customAnalyzer = createAnalyzer();
      const customPattern = {
        type: VulnerabilityType.DeprecatedFunction,
        severity: Severity.Low,
        name: 'Custom Test Pattern',
        description: 'Test pattern',
        recommendation: 'Test recommendation',
        patterns: [/test_pattern/gi]
      };

      const initialLength = customAnalyzer.getPatterns().length;
      customAnalyzer.addCustomPattern(customPattern);
      const patterns = customAnalyzer.getPatterns();
      expect(patterns.length).toBe(initialLength + 1);
    });

    it('should remove patterns', () => {
      const customAnalyzer = createAnalyzer();
      customAnalyzer.removePattern(VulnerabilityType.Reentrancy);
      const patterns = customAnalyzer.getPatterns();
      const hasReentrancy = patterns.some(p => p.type === VulnerabilityType.Reentrancy);
      expect(hasReentrancy).toBe(false);
    });
  });
});

describe('New Vulnerability Pattern Detection', () => {
  describe('DelegateCall Detection', () => {
    it('should detect unsafe delegatecall', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract ProxyContract {
    address public implementation;

    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);
        require(success);
    }
}
`;
      const testPath = path.join(__dirname, 'delegatecall-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const delegateCallIssues = result.results.filter(
          r => r.type === VulnerabilityType.DelegateCall
        );
        expect(delegateCallIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('TxOrigin Detection', () => {
    it('should detect tx.origin authentication', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract VulnerableAuth {
    address owner;

    function transfer(address to, uint amount) external {
        require(tx.origin == owner);
        payable(to).transfer(amount);
    }
}
`;
      const testPath = path.join(__dirname, 'txorigin-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const txOriginIssues = result.results.filter(
          r => r.type === VulnerabilityType.TxOrigin
        );
        expect(txOriginIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('Signature Malleability Detection', () => {
    it('should detect ecrecover usage', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract SignatureVerifier {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}
`;
      const testPath = path.join(__dirname, 'ecrecover-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const sigIssues = result.results.filter(
          r => r.type === VulnerabilityType.SignatureMalleability
        );
        expect(sigIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('Hardcoded Address Detection', () => {
    it('should detect hardcoded addresses', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract HardcodedAddr {
    function sendToOwner() external {
        payable(0x1234567890123456789012345678901234567890).transfer(msg.value);
    }
}
`;
      const testPath = path.join(__dirname, 'hardcoded-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const hardcodedIssues = result.results.filter(
          r => r.type === VulnerabilityType.HardcodedAddress
        );
        expect(hardcodedIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('Missing Zero Check Detection', () => {
    it('should detect missing zero address validation', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract TokenTransfer {
    function transferTo(address recipient, uint amount) external {
        require(amount > 0);
        // Missing zero address check for recipient
    }
}
`;
      const testPath = path.join(__dirname, 'zerocheck-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const zeroCheckIssues = result.results.filter(
          r => r.type === VulnerabilityType.MissingZeroCheck
        );
        expect(zeroCheckIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('Unprotected Initialize Detection', () => {
    it('should detect unprotected initialize function', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract UpgradeableContract {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }
}
`;
      const testPath = path.join(__dirname, 'initialize-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const initIssues = result.results.filter(
          r => r.type === VulnerabilityType.UnprotectedInitialize
        );
        expect(initIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });

  describe('Unsafe Cast Detection', () => {
    it('should detect unsafe type casting', () => {
      const testContract = `
pragma solidity ^0.8.0;

contract UnsafeCast {
    function convert(uint256 value) external pure returns (uint8) {
        return uint8(value);
    }

    function toAddress(uint256 val) external pure returns (address) {
        return address(val);
    }
}
`;
      const testPath = path.join(__dirname, 'unsafecast-test.sol');
      fs.writeFileSync(testPath, testContract);

      try {
        const analyzer = createAnalyzer();
        const result = analyzer.analyzeFile(testPath);
        const castIssues = result.results.filter(
          r => r.type === VulnerabilityType.UnsafeCast
        );
        expect(castIssues.length).toBeGreaterThan(0);
      } finally {
        if (fs.existsSync(testPath)) {
          fs.unlinkSync(testPath);
        }
      }
    });
  });
});

describe('Utils', () => {
  describe('readSolidityFile', () => {
    it('should read a Solidity file', () => {
      const testContent = 'contract Test {}';
      const testPath = path.join(__dirname, 'read-test.sol');
      fs.writeFileSync(testPath, testContent);

      const result = readSolidityFile(testPath);

      expect(result.path).toBe(testPath);
      expect(result.content).toBe(testContent);
      expect(result.lines.length).toBe(1);

      fs.unlinkSync(testPath);
    });
  });

  describe('extractLine', () => {
    const content = 'line1\nline2\nline3';

    it('should extract line 1', () => {
      expect(extractLine(content, 1)).toBe('line1');
    });

    it('should extract line 2', () => {
      expect(extractLine(content, 2)).toBe('line2');
    });

    it('should return empty for out of bounds', () => {
      expect(extractLine(content, 10)).toBe('');
    });
  });

  describe('getSurroundingLines', () => {
    const content = 'line1\nline2\nline3\nline4\nline5';

    it('should get surrounding lines', () => {
      const result = getSurroundingLines(content, 3, 1);
      expect(result.before).toEqual(['line2']);
      expect(result.target).toBe('line3');
      expect(result.after).toEqual(['line4']);
    });
  });

  describe('formatSeverity', () => {
    it('should format critical severity', () => {
      const formatted = formatSeverity(Severity.Critical);
      expect(formatted).toContain('CRITICAL');
    });

    it('should format high severity', () => {
      const formatted = formatSeverity(Severity.High);
      expect(formatted).toContain('HIGH');
    });
  });

  describe('generateSummary', () => {
    it('should generate summary with correct counts', () => {
      const mockResults = [
        { type: VulnerabilityType.Reentrancy, severity: Severity.Critical, name: 'Test', description: 'Test', recommendation: 'Test', line: 1, code: 'test' },
        { type: VulnerabilityType.Reentrancy, severity: Severity.Critical, name: 'Test', description: 'Test', recommendation: 'Test', line: 2, code: 'test' },
        { type: VulnerabilityType.IntegerOverflow, severity: Severity.High, name: 'Test', description: 'Test', recommendation: 'Test', line: 3, code: 'test' }
      ];

      const summary = generateSummary(mockResults);

      expect(summary.total).toBe(3);
      expect(summary.bySeverity[Severity.Critical]).toBe(2);
      expect(summary.bySeverity[Severity.High]).toBe(1);
      expect(summary.riskScore).toBeGreaterThan(0);
    });

    it('should handle empty results', () => {
      const summary = generateSummary([]);
      expect(summary.total).toBe(0);
      expect(summary.riskScore).toBe(0);
    });
  });

  describe('isCommentLine', () => {
    it('should identify single-line comments', () => {
      expect(isCommentLine('// This is a comment')).toBe(true);
    });

    it('should identify multi-line comment start', () => {
      expect(isCommentLine('/* This is a comment')).toBe(true);
    });

    it('should identify multi-line comment continuation', () => {
      expect(isCommentLine(' * This is a comment')).toBe(true);
    });

    it('should reject non-comments', () => {
      expect(isCommentLine('contract Test {}')).toBe(false);
    });
  });

  describe('getContractName', () => {
    it('should extract contract name', () => {
      const content = 'contract MyToken is ERC20 {';
      expect(getContractName(content)).toBe('MyToken');
    });

    it('should return null for no contract', () => {
      expect(getContractName('just some text without keyword')).toBeNull();
      expect(getContractName('')).toBeNull();
    });
  });

  describe('getPragmaVersion', () => {
    it('should extract pragma version', () => {
      const content = 'pragma solidity ^0.8.0;';
      expect(getPragmaVersion(content)).toBe('^0.8.0');
    });

    it('should return null for no pragma', () => {
      expect(getPragmaVersion('no pragma here')).toBeNull();
    });
  });

  describe('normalizeWhitespace', () => {
    it('should normalize multiple spaces', () => {
      expect(normalizeWhitespace('a   b    c')).toBe('a b c');
    });

    it('should trim whitespace', () => {
      expect(normalizeWhitespace('  test  ')).toBe('test');
    });
  });

  describe('filterComments', () => {
    it('should filter out comment lines', () => {
      const lines = ['// comment', 'code', '/* comment', 'more code'];
      const filtered = filterComments(lines);
      expect(filtered).toEqual(['code', 'more code']);
    });
  });

  describe('findStateVariables', () => {
    it('should find state variables', () => {
      const content = `
        contract Test {
            uint256 public balance;
            address owner;
            mapping(address => uint) balances;
        }
      `;
      const vars = findStateVariables(content);
      expect(vars).toContain('owner');
      expect(vars).toContain('balances');
    });
  });

  describe('findFunctions', () => {
    it('should find functions with metadata', () => {
      const content = `
        contract Test {
            function testFunc(uint a) external pure returns (uint) {
                return a;
            }
        }
      `;
      const functions = findFunctions(content);
      expect(functions.length).toBeGreaterThan(0);
      expect(functions[0].name).toBe('testFunc');
    });
  });

  describe('findEvents', () => {
    it('should find event definitions', () => {
      const content = `
        contract Test {
            event Transfer(address indexed from, address indexed to);
            event Approval(address indexed owner, address indexed spender);
        }
      `;
      const events = findEvents(content);
      expect(events).toContain('Transfer');
      expect(events).toContain('Approval');
    });
  });

  describe('findModifiers', () => {
    it('should find modifier definitions', () => {
      const content = `
        contract Test {
            modifier onlyOwner() { _; }
            modifier whenNotPaused() { _; }
        }
      `;
      const modifiers = findModifiers(content);
      expect(modifiers).toContain('onlyOwner');
      expect(modifiers).toContain('whenNotPaused');
    });
  });

  describe('countLines', () => {
    it('should count lines correctly', () => {
      const content = `line1
// comment
line3

line5`;
      const counts = countLines(content);
      expect(counts.total).toBe(5);
      expect(counts.comments).toBe(1);
      expect(counts.blank).toBe(1);
      expect(counts.code).toBe(3);
    });
  });

  describe('getInheritanceChain', () => {
    it('should extract inheritance chain', () => {
      const content = 'contract MyToken is ERC20, Ownable {';
      const chain = getInheritanceChain(content);
      expect(chain).toContain('ERC20');
      expect(chain).toContain('Ownable');
    });
  });

  describe('isUpgradeable', () => {
    it('should detect upgradeable contracts', () => {
      const content = `
        contract UpgradeableContract is Initializable {
            function initialize() public initializer {}
        }
      `;
      expect(isUpgradeable(content)).toBe(true);
    });

    it('should return false for non-upgradeable contracts', () => {
      const content = 'contract SimpleContract {}';
      expect(isUpgradeable(content)).toBe(false);
    });
  });
});

describe('Integration Tests', () => {
  it('should perform full analysis workflow', () => {
    const testContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract SafeContract {
    mapping(address => uint) private balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }
}
`;

    const testPath = path.join(__dirname, 'safe-contract.sol');
    fs.writeFileSync(testPath, testContract);

    try {
      const analyzer = createAnalyzer();
      const result = analyzer.analyzeFile(testPath);

      expect(result.contractName).toBe('SafeContract');
      expect(result.pragmaVersion).toBe('^0.7.0');
    } finally {
      if (fs.existsSync(testPath)) {
        fs.unlinkSync(testPath);
      }
    }
  });

  it('should analyze comprehensive vulnerable contract', () => {
    const testContract = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract ComprehensiveVulnerable {
    address public owner;
    uint256 public balance;
    address public implementation;

    event Deposit(address indexed user, uint256 amount);

    function deposit() external payable {
        balance += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(tx.origin == owner);
        (bool success, ) = msg.sender.call{value: amount}("");
        balance -= amount;
    }

    function upgrade(address newImpl) external {
        implementation = newImpl;
    }

    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);
        require(success);
    }

    function getRandom() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    function transferTo(address recipient, uint256 amount) external {
        payable(0x1234567890123456789012345678901234567890).transfer(amount);
    }

    function kill() external {
        selfdestruct(payable(owner));
    }
}
`;

    const testPath = path.join(__dirname, 'comprehensive-test.sol');
    fs.writeFileSync(testPath, testContract);

    try {
      const analyzer = createAnalyzer();
      const result = analyzer.analyzeFile(testPath);

      expect(result.contractName).toBe('ComprehensiveVulnerable');
      expect(result.results.length).toBeGreaterThan(5);

      const types = result.results.map(r => r.type);
      expect(types).toContain(VulnerabilityType.TxOrigin);
      expect(types).toContain(VulnerabilityType.DelegateCall);
      expect(types).toContain(VulnerabilityType.WeakRandomness);
      expect(types).toContain(VulnerabilityType.HardcodedAddress);
    } finally {
      if (fs.existsSync(testPath)) {
        fs.unlinkSync(testPath);
      }
    }
  });
});
