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
  filterComments
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

    it('should return undefined for non-existent type', () => {
      const pattern = getPatternByType('nonexistent' as VulnerabilityType);
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
      expect(result.contractName).toBe('VulnerableContract');
      expect(result.pragmaVersion).toBe('^0.7.0');
      expect(result.linesAnalyzed).toBeGreaterThan(0);
      expect(result.results.length).toBeGreaterThan(0);
    });

    it('should detect reentrancy vulnerability', () => {
      const result = analyzer.analyzeFile(testContractPath);
      const reentrancyIssues = result.results.filter(
        r => r.type === VulnerabilityType.Reentrancy
      );
      expect(reentrancyIssues.length).toBeGreaterThan(0);
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
      
      customAnalyzer.addCustomPattern(customPattern);
      const patterns = customAnalyzer.getPatterns();
      expect(patterns.length).toBeGreaterThan(VULNERABILITY_PATTERNS.length);
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
      expect(getContractName('no contract here')).toBeNull();
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
});
