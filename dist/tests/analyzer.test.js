"use strict";
/**
 * Unit tests for the Smart Contract Security Analyzer.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const analyzer_1 = require("../src/analyzer");
const patterns_1 = require("../src/patterns");
const utils_1 = require("../src/utils");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
describe('Vulnerability Patterns', () => {
    describe('getPatternByType', () => {
        it('should return pattern for reentrancy', () => {
            const pattern = (0, patterns_1.getPatternByType)(patterns_1.VulnerabilityType.Reentrancy);
            expect(pattern).toBeDefined();
            expect(pattern?.type).toBe(patterns_1.VulnerabilityType.Reentrancy);
            expect(pattern?.severity).toBe(patterns_1.Severity.Critical);
        });
        it('should return pattern for integer overflow', () => {
            const pattern = (0, patterns_1.getPatternByType)(patterns_1.VulnerabilityType.IntegerOverflow);
            expect(pattern).toBeDefined();
            expect(pattern?.severity).toBe(patterns_1.Severity.High);
        });
        it('should return pattern for delegatecall', () => {
            const pattern = (0, patterns_1.getPatternByType)(patterns_1.VulnerabilityType.DelegateCall);
            expect(pattern).toBeDefined();
            expect(pattern?.severity).toBe(patterns_1.Severity.Critical);
        });
        it('should return pattern for tx origin', () => {
            const pattern = (0, patterns_1.getPatternByType)(patterns_1.VulnerabilityType.TxOrigin);
            expect(pattern).toBeDefined();
            expect(pattern?.severity).toBe(patterns_1.Severity.High);
        });
        it('should return pattern for signature malleability', () => {
            const pattern = (0, patterns_1.getPatternByType)(patterns_1.VulnerabilityType.SignatureMalleability);
            expect(pattern).toBeDefined();
            expect(pattern?.severity).toBe(patterns_1.Severity.High);
        });
        it('should return undefined for non-existent type', () => {
            const pattern = (0, patterns_1.getPatternByType)('nonexistent');
            expect(pattern).toBeUndefined();
        });
    });
    describe('getPatternsBySeverity', () => {
        it('should return all critical patterns', () => {
            const patterns = (0, patterns_1.getPatternsBySeverity)(patterns_1.Severity.Critical);
            expect(patterns.length).toBeGreaterThan(0);
            patterns.forEach(p => expect(p.severity).toBe(patterns_1.Severity.Critical));
        });
        it('should return all high severity patterns', () => {
            const patterns = (0, patterns_1.getPatternsBySeverity)(patterns_1.Severity.High);
            expect(patterns.length).toBeGreaterThan(0);
            patterns.forEach(p => expect(p.severity).toBe(patterns_1.Severity.High));
        });
    });
    describe('VULNERABILITY_PATTERNS', () => {
        it('should have all required fields', () => {
            patterns_1.VULNERABILITY_PATTERNS.forEach(pattern => {
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
                patterns_1.VulnerabilityType.DelegateCall,
                patterns_1.VulnerabilityType.TxOrigin,
                patterns_1.VulnerabilityType.SignatureMalleability,
                patterns_1.VulnerabilityType.HardcodedAddress,
                patterns_1.VulnerabilityType.MissingZeroCheck,
                patterns_1.VulnerabilityType.UnsafeERC20,
                patterns_1.VulnerabilityType.UnprotectedInitialize,
                patterns_1.VulnerabilityType.UnsafeCast,
                patterns_1.VulnerabilityType.Shadowing
            ];
            newTypes.forEach(type => {
                const pattern = (0, patterns_1.getPatternByType)(type);
                expect(pattern).toBeDefined();
            });
        });
    });
});
describe('SmartContractAnalyzer', () => {
    let analyzer;
    let testContractPath;
    beforeAll(() => {
        analyzer = (0, analyzer_1.createAnalyzer)();
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
            const defaultAnalyzer = (0, analyzer_1.createAnalyzer)();
            expect(defaultAnalyzer).toBeInstanceOf(analyzer_1.SmartContractAnalyzer);
        });
        it('should create analyzer with custom options', () => {
            const options = {
                excludePatterns: [patterns_1.VulnerabilityType.Reentrancy],
                includeWarnings: false
            };
            const customAnalyzer = (0, analyzer_1.createAnalyzer)(options);
            expect(customAnalyzer).toBeInstanceOf(analyzer_1.SmartContractAnalyzer);
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
            }
            finally {
                if (fs.existsSync(testPath)) {
                    fs.unlinkSync(testPath);
                }
            }
        });
        it('should detect timestamp dependence', () => {
            const result = analyzer.analyzeFile(testContractPath);
            const timestampIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.TimestampDependence);
            expect(timestampIssues.length).toBeGreaterThan(0);
        });
        it('should detect weak randomness', () => {
            const result = analyzer.analyzeFile(testContractPath);
            const randomnessIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.WeakRandomness);
            expect(randomnessIssues.length).toBeGreaterThan(0);
        });
        it('should detect DoS vulnerability', () => {
            const result = analyzer.analyzeFile(testContractPath);
            const dosIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.DenialOfService);
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
            const customAnalyzer = (0, analyzer_1.createAnalyzer)();
            const customPattern = {
                type: patterns_1.VulnerabilityType.DeprecatedFunction,
                severity: patterns_1.Severity.Low,
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
            const customAnalyzer = (0, analyzer_1.createAnalyzer)();
            customAnalyzer.removePattern(patterns_1.VulnerabilityType.Reentrancy);
            const patterns = customAnalyzer.getPatterns();
            const hasReentrancy = patterns.some(p => p.type === patterns_1.VulnerabilityType.Reentrancy);
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const delegateCallIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.DelegateCall);
                expect(delegateCallIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const txOriginIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.TxOrigin);
                expect(txOriginIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const sigIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.SignatureMalleability);
                expect(sigIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const hardcodedIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.HardcodedAddress);
                expect(hardcodedIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const zeroCheckIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.MissingZeroCheck);
                expect(zeroCheckIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const initIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.UnprotectedInitialize);
                expect(initIssues.length).toBeGreaterThan(0);
            }
            finally {
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
                const analyzer = (0, analyzer_1.createAnalyzer)();
                const result = analyzer.analyzeFile(testPath);
                const castIssues = result.results.filter(r => r.type === patterns_1.VulnerabilityType.UnsafeCast);
                expect(castIssues.length).toBeGreaterThan(0);
            }
            finally {
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
            const result = (0, utils_1.readSolidityFile)(testPath);
            expect(result.path).toBe(testPath);
            expect(result.content).toBe(testContent);
            expect(result.lines.length).toBe(1);
            fs.unlinkSync(testPath);
        });
    });
    describe('extractLine', () => {
        const content = 'line1\nline2\nline3';
        it('should extract line 1', () => {
            expect((0, utils_1.extractLine)(content, 1)).toBe('line1');
        });
        it('should extract line 2', () => {
            expect((0, utils_1.extractLine)(content, 2)).toBe('line2');
        });
        it('should return empty for out of bounds', () => {
            expect((0, utils_1.extractLine)(content, 10)).toBe('');
        });
    });
    describe('getSurroundingLines', () => {
        const content = 'line1\nline2\nline3\nline4\nline5';
        it('should get surrounding lines', () => {
            const result = (0, utils_1.getSurroundingLines)(content, 3, 1);
            expect(result.before).toEqual(['line2']);
            expect(result.target).toBe('line3');
            expect(result.after).toEqual(['line4']);
        });
    });
    describe('formatSeverity', () => {
        it('should format critical severity', () => {
            const formatted = (0, utils_1.formatSeverity)(patterns_1.Severity.Critical);
            expect(formatted).toContain('CRITICAL');
        });
        it('should format high severity', () => {
            const formatted = (0, utils_1.formatSeverity)(patterns_1.Severity.High);
            expect(formatted).toContain('HIGH');
        });
    });
    describe('generateSummary', () => {
        it('should generate summary with correct counts', () => {
            const mockResults = [
                { type: patterns_1.VulnerabilityType.Reentrancy, severity: patterns_1.Severity.Critical, name: 'Test', description: 'Test', recommendation: 'Test', line: 1, code: 'test' },
                { type: patterns_1.VulnerabilityType.Reentrancy, severity: patterns_1.Severity.Critical, name: 'Test', description: 'Test', recommendation: 'Test', line: 2, code: 'test' },
                { type: patterns_1.VulnerabilityType.IntegerOverflow, severity: patterns_1.Severity.High, name: 'Test', description: 'Test', recommendation: 'Test', line: 3, code: 'test' }
            ];
            const summary = (0, utils_1.generateSummary)(mockResults);
            expect(summary.total).toBe(3);
            expect(summary.bySeverity[patterns_1.Severity.Critical]).toBe(2);
            expect(summary.bySeverity[patterns_1.Severity.High]).toBe(1);
            expect(summary.riskScore).toBeGreaterThan(0);
        });
        it('should handle empty results', () => {
            const summary = (0, utils_1.generateSummary)([]);
            expect(summary.total).toBe(0);
            expect(summary.riskScore).toBe(0);
        });
    });
    describe('isCommentLine', () => {
        it('should identify single-line comments', () => {
            expect((0, utils_1.isCommentLine)('// This is a comment')).toBe(true);
        });
        it('should identify multi-line comment start', () => {
            expect((0, utils_1.isCommentLine)('/* This is a comment')).toBe(true);
        });
        it('should identify multi-line comment continuation', () => {
            expect((0, utils_1.isCommentLine)(' * This is a comment')).toBe(true);
        });
        it('should reject non-comments', () => {
            expect((0, utils_1.isCommentLine)('contract Test {}')).toBe(false);
        });
    });
    describe('getContractName', () => {
        it('should extract contract name', () => {
            const content = 'contract MyToken is ERC20 {';
            expect((0, utils_1.getContractName)(content)).toBe('MyToken');
        });
        it('should return null for no contract', () => {
            expect((0, utils_1.getContractName)('just some text without keyword')).toBeNull();
            expect((0, utils_1.getContractName)('')).toBeNull();
        });
    });
    describe('getPragmaVersion', () => {
        it('should extract pragma version', () => {
            const content = 'pragma solidity ^0.8.0;';
            expect((0, utils_1.getPragmaVersion)(content)).toBe('^0.8.0');
        });
        it('should return null for no pragma', () => {
            expect((0, utils_1.getPragmaVersion)('no pragma here')).toBeNull();
        });
    });
    describe('normalizeWhitespace', () => {
        it('should normalize multiple spaces', () => {
            expect((0, utils_1.normalizeWhitespace)('a   b    c')).toBe('a b c');
        });
        it('should trim whitespace', () => {
            expect((0, utils_1.normalizeWhitespace)('  test  ')).toBe('test');
        });
    });
    describe('filterComments', () => {
        it('should filter out comment lines', () => {
            const lines = ['// comment', 'code', '/* comment', 'more code'];
            const filtered = (0, utils_1.filterComments)(lines);
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
            const vars = (0, utils_1.findStateVariables)(content);
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
            const functions = (0, utils_1.findFunctions)(content);
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
            const events = (0, utils_1.findEvents)(content);
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
            const modifiers = (0, utils_1.findModifiers)(content);
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
            const counts = (0, utils_1.countLines)(content);
            expect(counts.total).toBe(5);
            expect(counts.comments).toBe(1);
            expect(counts.blank).toBe(1);
            expect(counts.code).toBe(3);
        });
    });
    describe('getInheritanceChain', () => {
        it('should extract inheritance chain', () => {
            const content = 'contract MyToken is ERC20, Ownable {';
            const chain = (0, utils_1.getInheritanceChain)(content);
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
            expect((0, utils_1.isUpgradeable)(content)).toBe(true);
        });
        it('should return false for non-upgradeable contracts', () => {
            const content = 'contract SimpleContract {}';
            expect((0, utils_1.isUpgradeable)(content)).toBe(false);
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
            const analyzer = (0, analyzer_1.createAnalyzer)();
            const result = analyzer.analyzeFile(testPath);
            expect(result.contractName).toBe('SafeContract');
            expect(result.pragmaVersion).toBe('^0.7.0');
        }
        finally {
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
            const analyzer = (0, analyzer_1.createAnalyzer)();
            const result = analyzer.analyzeFile(testPath);
            expect(result.contractName).toBe('ComprehensiveVulnerable');
            expect(result.results.length).toBeGreaterThan(5);
            const types = result.results.map(r => r.type);
            expect(types).toContain(patterns_1.VulnerabilityType.TxOrigin);
            expect(types).toContain(patterns_1.VulnerabilityType.DelegateCall);
            expect(types).toContain(patterns_1.VulnerabilityType.WeakRandomness);
            expect(types).toContain(patterns_1.VulnerabilityType.HardcodedAddress);
        }
        finally {
            if (fs.existsSync(testPath)) {
                fs.unlinkSync(testPath);
            }
        }
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5hbHl6ZXIudGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3Rlc3RzL2FuYWx5emVyLnRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBOztHQUVHOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUVILDhDQUt5QjtBQUN6Qiw4Q0FNeUI7QUFDekIsd0NBa0JzQjtBQUN0Qix1Q0FBeUI7QUFDekIsMkNBQTZCO0FBRTdCLFFBQVEsQ0FBQyx3QkFBd0IsRUFBRSxHQUFHLEVBQUU7SUFDdEMsUUFBUSxDQUFDLGtCQUFrQixFQUFFLEdBQUcsRUFBRTtRQUNoQyxFQUFFLENBQUMsc0NBQXNDLEVBQUUsR0FBRyxFQUFFO1lBQzlDLE1BQU0sT0FBTyxHQUFHLElBQUEsMkJBQWdCLEVBQUMsNEJBQWlCLENBQUMsVUFBVSxDQUFDLENBQUM7WUFDL0QsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO1lBQzlCLE1BQU0sQ0FBQyxPQUFPLEVBQUUsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLDRCQUFpQixDQUFDLFVBQVUsQ0FBQyxDQUFDO1lBQ3pELE1BQU0sQ0FBQyxPQUFPLEVBQUUsUUFBUSxDQUFDLENBQUMsSUFBSSxDQUFDLG1CQUFRLENBQUMsUUFBUSxDQUFDLENBQUM7UUFDcEQsQ0FBQyxDQUFDLENBQUM7UUFFSCxFQUFFLENBQUMsNENBQTRDLEVBQUUsR0FBRyxFQUFFO1lBQ3BELE1BQU0sT0FBTyxHQUFHLElBQUEsMkJBQWdCLEVBQUMsNEJBQWlCLENBQUMsZUFBZSxDQUFDLENBQUM7WUFDcEUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO1lBQzlCLE1BQU0sQ0FBQyxPQUFPLEVBQUUsUUFBUSxDQUFDLENBQUMsSUFBSSxDQUFDLG1CQUFRLENBQUMsSUFBSSxDQUFDLENBQUM7UUFDaEQsQ0FBQyxDQUFDLENBQUM7UUFFSCxFQUFFLENBQUMsd0NBQXdD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QUMsUUFBUSxDQUFDLEVBQUUsQ0FBQztnQkFDNUIsRUFBRSxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsQ0FBQztZQUMxQixDQUFDO1FBQ0gsQ0FBQztJQUNILENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQyxDQUFDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFVuaXQgdGVzdHMgZm9yIHRoZSBTbWFydCBDb250cmFjdCBTZWN1cml0eSBBbmFseXplci5cbiAqL1xuXG5pbXBvcnQge1xuICBTbWFydENvbnRyYWN0QW5hbHl6ZXIsXG4gIGNyZWF0ZUFuYWx5emVyLFxuICBhbmFseXplQ29udHJhY3RzLFxuICBBbmFseXplck9wdGlvbnNcbn0gZnJvbSAnLi4vc3JjL2FuYWx5emVyJztcbmltcG9ydCB7XG4gIFZ1bG5lcmFiaWxpdHlUeXBlLFxuICBTZXZlcml0eSxcbiAgVlVMTkVSQUJJTElUWV9QQVRURVJOUyxcbiAgZ2V0UGF0dGVybkJ5VHlwZSxcbiAgZ2V0UGF0dGVybnNCeVNldmVyaXR5XG59IGZyb20gJy4uL3NyYy9wYXR0ZXJucyc7XG5pbXBvcnQge1xuICByZWFkU29saWRpdHlGaWxlLFxuICBleHRyYWN0TGluZSxcbiAgZ2V0U3Vycm91bmRpbmdMaW5lcyxcbiAgZm9ybWF0U2V2ZXJpdHksXG4gIGdlbmVyYXRlU3VtbWFyeSxcbiAgaXNDb21tZW50TGluZSxcbiAgZ2V0Q29udHJhY3ROYW1lLFxuICBnZXRQcmFnbWFWZXJzaW9uLFxuICBub3JtYWxpemVXaGl0ZXNwYWNlLFxuICBmaWx0ZXJDb21tZW50cyxcbiAgZmluZFN0YXRlVmFyaWFibGVzLFxuICBmaW5kRnVuY3Rpb25zLFxuICBmaW5kRXZlbnRzLFxuICBmaW5kTW9kaWZpZXJzLFxuICBjb3VudExpbmVzLFxuICBnZXRJbmhlcml0YW5jZUNoYWluLFxuICBpc1VwZ3JhZGVhYmxlXG59IGZyb20gJy4uL3NyYy91dGlscyc7XG5pbXBvcnQgKiBhcyBmcyBmcm9tICdmcyc7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuXG5kZXNjcmliZSgnVnVsbmVyYWJpbGl0eSBQYXR0ZXJucycsICgpID0+IHtcbiAgZGVzY3JpYmUoJ2dldFBhdHRlcm5CeVR5cGUnLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gcGF0dGVybiBmb3IgcmVlbnRyYW5jeScsICgpID0+IHtcbiAgICAgIGNvbnN0IHBhdHRlcm4gPSBnZXRQYXR0ZXJuQnlUeXBlKFZ1bG5lcmFiaWxpdHlUeXBlLlJlZW50cmFuY3kpO1xuICAgICAgZXhwZWN0KHBhdHRlcm4pLnRvQmVEZWZpbmVkKCk7XG4gICAgICBleHBlY3QocGF0dGVybj8udHlwZSkudG9CZShWdWxuZXJhYmlsaXR5VHlwZS5SZWVudHJhbmN5KTtcbiAgICAgIGV4cGVjdChwYXR0ZXJuPy5zZXZlcml0eSkudG9CZShTZXZlcml0eS5Dcml0aWNhbCk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIHJldHVybiBwYXR0ZXJuIGZvciBpbnRlZ2VyIG92ZXJmbG93JywgKCkgPT4ge1xuICAgICAgY29uc3QgcGF0dGVybiA9IGdldFBhdHRlcm5CeVR5cGUoVnVsbmVyYWJpbGl0eVR5cGUuSW50ZWdlck92ZXJmbG93KTtcbiAgICAgIGV4cGVjdChwYXR0ZXJuKS50b0JlRGVmaW5lZCgpO1xuICAgICAgZXhwZWN0KHBhdHRlcm4/LnNldmVyaXR5KS50b0JlKFNldmVyaXR5LkhpZ2gpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gcGF0dGVybiBmb3IgZGVsZWdhdGVjYWxsJywgKCkgPT4ge1xuICAgICAgY29uc3QgcGF0dGVybiA9IGdldFBhdHRlcm5CeVR5cGUoVnVsbmVyYWJpbGl0eVR5cGUuRGVsZWdhdGVDYWxsKTtcbiAgICAgIGV4cGVjdChwYXR0ZXJuKS50b0JlRGVmaW5lZCgpO1xuICAgICAgZXhwZWN0KHBhdHRlcm4/LnNldmVyaXR5KS50b0JlKFNldmVyaXR5LkNyaXRpY2FsKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgcmV0dXJuIHBhdHRlcm4gZm9yIHR4IG9yaWdpbicsICgpID0+IHtcbiAgICAgIGNvbnN0IHBhdHRlcm4gPSBnZXRQYXR0ZXJuQnlUeXBlKFZ1bG5lcmFiaWxpdHlUeXBlLlR4T3JpZ2luKTtcbiAgICAgIGV4cGVjdChwYXR0ZXJuKS50b0JlRGVmaW5lZCgpO1xuICAgICAgZXhwZWN0KHBhdHRlcm4/LnNldmVyaXR5KS50b0JlKFNldmVyaXR5LkhpZ2gpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gcGF0dGVybiBmb3Igc2lnbmF0dXJlIG1hbGxlYWJpbGl0eScsICgpID0+IHtcbiAgICAgIGNvbnN0IHBhdHRlcm4gPSBnZXRQYXR0ZXJuQnlUeXBlKFZ1bG5lcmFiaWxpdHlUeXBlLlNpZ25hdHVyZU1hbGxlYWJpbGl0eSk7XG4gICAgICBleHBlY3QocGF0dGVybikudG9CZURlZmluZWQoKTtcbiAgICAgIGV4cGVjdChwYXR0ZXJuPy5zZXZlcml0eSkudG9CZShTZXZlcml0eS5IaWdoKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgcmV0dXJuIHVuZGVmaW5lZCBmb3Igbm9uLWV4aXN0ZW50IHR5cGUnLCAoKSA9PiB7XG4gICAgICBjb25zdCBwYXR0ZXJuID0gZ2V0UGF0dGVybkJ5VHlwZSgoJ25vbmV4aXN0ZW50JyBhcyB1bmtub3duKSBhcyBWdWxuZXJhYmlsaXR5VHlwZSk7XG4gICAgICBleHBlY3QocGF0dGVybikudG9CZVVuZGVmaW5lZCgpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZ2V0UGF0dGVybnNCeVNldmVyaXR5JywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgcmV0dXJuIGFsbCBjcml0aWNhbCBwYXR0ZXJucycsICgpID0+IHtcbiAgICAgIGNvbnN0IHBhdHRlcm5zID0gZ2V0UGF0dGVybnNCeVNldmVyaXR5KFNldmVyaXR5LkNyaXRpY2FsKTtcbiAgICAgIGV4cGVjdChwYXR0ZXJucy5sZW5ndGgpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICAgIHBhdHRlcm5zLmZvckVhY2gocCA9PiBleHBlY3QocC5zZXZlcml0eSkudG9CZShTZXZlcml0eS5Dcml0aWNhbCkpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gYWxsIGhpZ2ggc2V2ZXJpdHkgcGF0dGVybnMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBwYXR0ZXJucyA9IGdldFBhdHRlcm5zQnlTZXZlcml0eShTZXZlcml0eS5IaWdoKTtcbiAgICAgIGV4cGVjdChwYXR0ZXJucy5sZW5ndGgpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICAgIHBhdHRlcm5zLmZvckVhY2gocCA9PiBleHBlY3QocC5zZXZlcml0eSkudG9CZShTZXZlcml0eS5IaWdoKSk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdWVUxORVJBQklMSVRZX1BBVFRFUk5TJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgaGF2ZSBhbGwgcmVxdWlyZWQgZmllbGRzJywgKCkgPT4ge1xuICAgICAgVlVMTkVSQUJJTElUWV9QQVRURVJOUy5mb3JFYWNoKHBhdHRlcm4gPT4ge1xuICAgICAgICBleHBlY3QocGF0dGVybi50eXBlKS50b0JlRGVmaW5lZCgpO1xuICAgICAgICBleHBlY3QocGF0dGVybi5zZXZlcml0eSkudG9CZURlZmluZWQoKTtcbiAgICAgICAgZXhwZWN0KHBhdHRlcm4ubmFtZSkudG9CZURlZmluZWQoKTtcbiAgICAgICAgZXhwZWN0KHBhdHRlcm4uZGVzY3JpcHRpb24pLnRvQmVEZWZpbmVkKCk7XG4gICAgICAgIGV4cGVjdChwYXR0ZXJuLnJlY29tbWVuZGF0aW9uKS50b0JlRGVmaW5lZCgpO1xuICAgICAgICBleHBlY3QocGF0dGVybi5wYXR0ZXJucykudG9CZURlZmluZWQoKTtcbiAgICAgICAgZXhwZWN0KHBhdHRlcm4ucGF0dGVybnMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9KTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgaW5jbHVkZSBuZXcgdnVsbmVyYWJpbGl0eSB0eXBlcycsICgpID0+IHtcbiAgICAgIGNvbnN0IG5ld1R5cGVzID0gW1xuICAgICAgICBWdWxuZXJhYmlsaXR5VHlwZS5EZWxlZ2F0ZUNhbGwsXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLlR4T3JpZ2luLFxuICAgICAgICBWdWxuZXJhYmlsaXR5VHlwZS5TaWduYXR1cmVNYWxsZWFiaWxpdHksXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLkhhcmRjb2RlZEFkZHJlc3MsXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLk1pc3NpbmdaZXJvQ2hlY2ssXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLlVuc2FmZUVSQzIwLFxuICAgICAgICBWdWxuZXJhYmlsaXR5VHlwZS5VbnByb3RlY3RlZEluaXRpYWxpemUsXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLlVuc2FmZUNhc3QsXG4gICAgICAgIFZ1bG5lcmFiaWxpdHlUeXBlLlNoYWRvd2luZ1xuICAgICAgXTtcblxuICAgICAgbmV3VHlwZXMuZm9yRWFjaCh0eXBlID0+IHtcbiAgICAgICAgY29uc3QgcGF0dGVybiA9IGdldFBhdHRlcm5CeVR5cGUodHlwZSk7XG4gICAgICAgIGV4cGVjdChwYXR0ZXJuKS50b0JlRGVmaW5lZCgpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH0pO1xufSk7XG5cbmRlc2NyaWJlKCdTbWFydENvbnRyYWN0QW5hbHl6ZXInLCAoKSA9PiB7XG4gIGxldCBhbmFseXplcjogU21hcnRDb250cmFjdEFuYWx5emVyO1xuICBsZXQgdGVzdENvbnRyYWN0UGF0aDogc3RyaW5nO1xuXG4gIGJlZm9yZUFsbCgoKSA9PiB7XG4gICAgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuXG4gICAgY29uc3QgdGVzdENvbnRyYWN0ID0gYFxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IE1JVFxucHJhZ21hIHNvbGlkaXR5IF4wLjcuMDtcblxuY29udHJhY3QgVnVsbmVyaWJsZUNvbnRyYWN0IHtcbiAgICBtYXBwaW5nKGFkZHJlc3MgPT4gdWludCkgYmFsYW5jZXM7XG4gICAgdWludCB0b3RhbFN1cHBseTtcblxuICAgIGZ1bmN0aW9uIGRlcG9zaXQoKSBleHRlcm5hbCBwYXlhYmxlIHtcbiAgICAgICAgYmFsYW5jZXNbbXNnLnNlbmRlcl0gKz0gbXNnLnZhbHVlO1xuICAgICAgICB0b3RhbFN1cHBseSArPSBtc2cudmFsdWU7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gd2l0aGRyYXcodWludCBhbW91bnQpIGV4dGVybmFsIHtcbiAgICAgICAgcmVxdWlyZShiYWxhbmNlc1ttc2cuc2VuZGVyXSA+PSBhbW91bnQpO1xuICAgICAgICAoYm9vbCBzdWNjZXNzLCApID0gbXNnLnNlbmRlci5jYWxse3ZhbHVlOiBhbW91bnR9KFwiXCIpO1xuICAgICAgICByZXF1aXJlKHN1Y2Nlc3MpO1xuICAgICAgICBiYWxhbmNlc1ttc2cuc2VuZGVyXSAtPSBhbW91bnQ7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdHJhbnNmZXJPd25lcnNoaXAoYWRkcmVzcyBuZXdPd25lcikgZXh0ZXJuYWwge1xuICAgICAgICBvd25lciA9IG5ld093bmVyO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGtpbGwoKSBleHRlcm5hbCB7XG4gICAgICAgIHNlbGZkZXN0cnVjdChwYXlhYmxlKG1zZy5zZW5kZXIpKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRSYW5kb20oKSBleHRlcm5hbCB2aWV3IHJldHVybnMgKHVpbnQpIHtcbiAgICAgICAgcmV0dXJuIHVpbnQoa2VjY2FrMjU2KGFiaS5lbmNvZGVQYWNrZWQoYmxvY2sudGltZXN0YW1wLCBibG9jay5kaWZmaWN1bHR5KSkpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHByb2Nlc3NVc2VycyhhZGRyZXNzW10gbWVtb3J5IHVzZXJzKSBleHRlcm5hbCB7XG4gICAgICAgIGZvciAodWludCBpID0gMDsgaSA8IHVzZXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICByZXF1aXJlKHVzZXJzW2ldICE9IGFkZHJlc3MoMCkpO1xuICAgICAgICB9XG4gICAgfVxufVxuYDtcblxuICAgIHRlc3RDb250cmFjdFBhdGggPSBwYXRoLmpvaW4oX19kaXJuYW1lLCAndGVzdC1jb250cmFjdC5zb2wnKTtcbiAgICBmcy53cml0ZUZpbGVTeW5jKHRlc3RDb250cmFjdFBhdGgsIHRlc3RDb250cmFjdCk7XG4gIH0pO1xuXG4gIGFmdGVyQWxsKCgpID0+IHtcbiAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0Q29udHJhY3RQYXRoKSkge1xuICAgICAgZnMudW5saW5rU3luYyh0ZXN0Q29udHJhY3RQYXRoKTtcbiAgICB9XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdjb25zdHJ1Y3RvcicsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIGNyZWF0ZSBhbmFseXplciB3aXRoIGRlZmF1bHQgb3B0aW9ucycsICgpID0+IHtcbiAgICAgIGNvbnN0IGRlZmF1bHRBbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKCk7XG4gICAgICBleHBlY3QoZGVmYXVsdEFuYWx5emVyKS50b0JlSW5zdGFuY2VPZihTbWFydENvbnRyYWN0QW5hbHl6ZXIpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBjcmVhdGUgYW5hbHl6ZXIgd2l0aCBjdXN0b20gb3B0aW9ucycsICgpID0+IHtcbiAgICAgIGNvbnN0IG9wdGlvbnM6IEFuYWx5emVyT3B0aW9ucyA9IHtcbiAgICAgICAgZXhjbHVkZVBhdHRlcm5zOiBbVnVsbmVyYWJpbGl0eVR5cGUuUmVlbnRyYW5jeV0sXG4gICAgICAgIGluY2x1ZGVXYXJuaW5nczogZmFsc2VcbiAgICAgIH07XG4gICAgICBjb25zdCBjdXN0b21BbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKG9wdGlvbnMpO1xuICAgICAgZXhwZWN0KGN1c3RvbUFuYWx5emVyKS50b0JlSW5zdGFuY2VPZihTbWFydENvbnRyYWN0QW5hbHl6ZXIpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnYW5hbHl6ZUZpbGUnLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBhbmFseXplIGEgU29saWRpdHkgZmlsZSBhbmQgcmV0dXJuIHJlc3VsdHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0Q29udHJhY3RQYXRoKTtcblxuICAgICAgZXhwZWN0KHJlc3VsdC5maWxlKS50b0JlKHRlc3RDb250cmFjdFBhdGgpO1xuICAgICAgZXhwZWN0KHJlc3VsdC5jb250cmFjdE5hbWUpLnRvQmUoJ1Z1bG5lcmlibGVDb250cmFjdCcpO1xuICAgICAgZXhwZWN0KHJlc3VsdC5wcmFnbWFWZXJzaW9uKS50b0JlKCdeMC43LjAnKTtcbiAgICAgIGV4cGVjdChyZXN1bHQubGluZXNBbmFseXplZCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgICAgZXhwZWN0KHJlc3VsdC5yZXN1bHRzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgcmVlbnRyYW5jeSB2dWxuZXJhYmlsaXR5JywgKCkgPT4ge1xuICAgICAgY29uc3QgdGVzdENvbnRyYWN0ID0gYFxucHJhZ21hIHNvbGlkaXR5IF4wLjcuMDtcblxuY29udHJhY3QgUmVlbnRyYW5jeVRlc3Qge1xuICAgIG1hcHBpbmcoYWRkcmVzcyA9PiB1aW50KSBiYWxhbmNlcztcblxuICAgIGZ1bmN0aW9uIHdpdGhkcmF3KHVpbnQgYW1vdW50KSBleHRlcm5hbCB7XG4gICAgICAgIG93bmVyID0gbXNnLnNlbmRlcjtcbiAgICAgICAgKGJvb2wgc3VjY2VzcywgKSA9IG1zZy5zZW5kZXIuY2FsbHt2YWx1ZTogYW1vdW50fShcIlwiKTtcbiAgICB9XG59XG5gO1xuICAgICAgY29uc3QgdGVzdFBhdGggPSBwYXRoLmpvaW4oX19kaXJuYW1lLCAncmVlbnRyYW5jeS10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gYW5hbHl6ZXIuYW5hbHl6ZUZpbGUodGVzdFBhdGgpO1xuICAgICAgICBleHBlY3QocmVzdWx0LnJlc3VsdHMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgdGltZXN0YW1wIGRlcGVuZGVuY2UnLCAoKSA9PiB7XG4gICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0Q29udHJhY3RQYXRoKTtcbiAgICAgIGNvbnN0IHRpbWVzdGFtcElzc3VlcyA9IHJlc3VsdC5yZXN1bHRzLmZpbHRlcihcbiAgICAgICAgciA9PiByLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLlRpbWVzdGFtcERlcGVuZGVuY2VcbiAgICAgICk7XG4gICAgICBleHBlY3QodGltZXN0YW1wSXNzdWVzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBkZXRlY3Qgd2VhayByYW5kb21uZXNzJywgKCkgPT4ge1xuICAgICAgY29uc3QgcmVzdWx0ID0gYW5hbHl6ZXIuYW5hbHl6ZUZpbGUodGVzdENvbnRyYWN0UGF0aCk7XG4gICAgICBjb25zdCByYW5kb21uZXNzSXNzdWVzID0gcmVzdWx0LnJlc3VsdHMuZmlsdGVyKFxuICAgICAgICByID0+IHIudHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuV2Vha1JhbmRvbW5lc3NcbiAgICAgICk7XG4gICAgICBleHBlY3QocmFuZG9tbmVzc0lzc3Vlcy5sZW5ndGgpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgZGV0ZWN0IERvUyB2dWxuZXJhYmlsaXR5JywgKCkgPT4ge1xuICAgICAgY29uc3QgcmVzdWx0ID0gYW5hbHl6ZXIuYW5hbHl6ZUZpbGUodGVzdENvbnRyYWN0UGF0aCk7XG4gICAgICBjb25zdCBkb3NJc3N1ZXMgPSByZXN1bHQucmVzdWx0cy5maWx0ZXIoXG4gICAgICAgIHIgPT4gci50eXBlID09PSBWdWxuZXJhYmlsaXR5VHlwZS5EZW5pYWxPZlNlcnZpY2VcbiAgICAgICk7XG4gICAgICBleHBlY3QoZG9zSXNzdWVzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnYW5hbHl6ZUZpbGVzJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgYW5hbHl6ZSBtdWx0aXBsZSBmaWxlcycsICgpID0+IHtcbiAgICAgIGNvbnN0IHJlcG9ydCA9IGFuYWx5emVyLmFuYWx5emVGaWxlcyhbdGVzdENvbnRyYWN0UGF0aF0pO1xuXG4gICAgICBleHBlY3QocmVwb3J0LmZpbGVzLmxlbmd0aCkudG9CZSgxKTtcbiAgICAgIGV4cGVjdChyZXBvcnQudG90YWxJc3N1ZXMpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICAgIGV4cGVjdChyZXBvcnQudGltZXN0YW1wKS50b0JlRGVmaW5lZCgpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBoYW5kbGUgbm9uLWV4aXN0ZW50IGZpbGVzIGdyYWNlZnVsbHknLCAoKSA9PiB7XG4gICAgICBjb25zdCByZXBvcnQgPSBhbmFseXplci5hbmFseXplRmlsZXMoWycvbm9uZXhpc3RlbnQvZmlsZS5zb2wnXSk7XG5cbiAgICAgIGV4cGVjdChyZXBvcnQuZmlsZXMubGVuZ3RoKS50b0JlKDEpO1xuICAgICAgZXhwZWN0KHJlcG9ydC5maWxlc1swXS5yZXN1bHRzLmxlbmd0aCkudG9CZSgwKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ3BhdHRlcm4gbWFuYWdlbWVudCcsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIGFkZCBjdXN0b20gcGF0dGVybnMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBjdXN0b21BbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKCk7XG4gICAgICBjb25zdCBjdXN0b21QYXR0ZXJuID0ge1xuICAgICAgICB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5EZXByZWNhdGVkRnVuY3Rpb24sXG4gICAgICAgIHNldmVyaXR5OiBTZXZlcml0eS5Mb3csXG4gICAgICAgIG5hbWU6ICdDdXN0b20gVGVzdCBQYXR0ZXJuJyxcbiAgICAgICAgZGVzY3JpcHRpb246ICdUZXN0IHBhdHRlcm4nLFxuICAgICAgICByZWNvbW1lbmRhdGlvbjogJ1Rlc3QgcmVjb21tZW5kYXRpb24nLFxuICAgICAgICBwYXR0ZXJuczogWy90ZXN0X3BhdHRlcm4vZ2ldXG4gICAgICB9O1xuXG4gICAgICBjb25zdCBpbml0aWFsTGVuZ3RoID0gY3VzdG9tQW5hbHl6ZXIuZ2V0UGF0dGVybnMoKS5sZW5ndGg7XG4gICAgICBjdXN0b21BbmFseXplci5hZGRDdXN0b21QYXR0ZXJuKGN1c3RvbVBhdHRlcm4pO1xuICAgICAgY29uc3QgcGF0dGVybnMgPSBjdXN0b21BbmFseXplci5nZXRQYXR0ZXJucygpO1xuICAgICAgZXhwZWN0KHBhdHRlcm5zLmxlbmd0aCkudG9CZShpbml0aWFsTGVuZ3RoICsgMSk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIHJlbW92ZSBwYXR0ZXJucycsICgpID0+IHtcbiAgICAgIGNvbnN0IGN1c3RvbUFuYWx5emVyID0gY3JlYXRlQW5hbHl6ZXIoKTtcbiAgICAgIGN1c3RvbUFuYWx5emVyLnJlbW92ZVBhdHRlcm4oVnVsbmVyYWJpbGl0eVR5cGUuUmVlbnRyYW5jeSk7XG4gICAgICBjb25zdCBwYXR0ZXJucyA9IGN1c3RvbUFuYWx5emVyLmdldFBhdHRlcm5zKCk7XG4gICAgICBjb25zdCBoYXNSZWVudHJhbmN5ID0gcGF0dGVybnMuc29tZShwID0+IHAudHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuUmVlbnRyYW5jeSk7XG4gICAgICBleHBlY3QoaGFzUmVlbnRyYW5jeSkudG9CZShmYWxzZSk7XG4gICAgfSk7XG4gIH0pO1xufSk7XG5cbmRlc2NyaWJlKCdOZXcgVnVsbmVyYWJpbGl0eSBQYXR0ZXJuIERldGVjdGlvbicsICgpID0+IHtcbiAgZGVzY3JpYmUoJ0RlbGVnYXRlQ2FsbCBEZXRlY3Rpb24nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgdW5zYWZlIGRlbGVnYXRlY2FsbCcsICgpID0+IHtcbiAgICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbnByYWdtYSBzb2xpZGl0eSBeMC44LjA7XG5cbmNvbnRyYWN0IFByb3h5Q29udHJhY3Qge1xuICAgIGFkZHJlc3MgcHVibGljIGltcGxlbWVudGF0aW9uO1xuXG4gICAgZnVuY3Rpb24gZXhlY3V0ZShieXRlcyBjYWxsZGF0YSBkYXRhKSBleHRlcm5hbCB7XG4gICAgICAgIChib29sIHN1Y2Nlc3MsICkgPSBpbXBsZW1lbnRhdGlvbi5kZWxlZ2F0ZWNhbGwoZGF0YSk7XG4gICAgICAgIHJlcXVpcmUoc3VjY2Vzcyk7XG4gICAgfVxufVxuYDtcbiAgICAgIGNvbnN0IHRlc3RQYXRoID0gcGF0aC5qb2luKF9fZGlybmFtZSwgJ2RlbGVnYXRlY2FsbC10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG4gICAgICAgIGNvbnN0IGRlbGVnYXRlQ2FsbElzc3VlcyA9IHJlc3VsdC5yZXN1bHRzLmZpbHRlcihcbiAgICAgICAgICByID0+IHIudHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuRGVsZWdhdGVDYWxsXG4gICAgICAgICk7XG4gICAgICAgIGV4cGVjdChkZWxlZ2F0ZUNhbGxJc3N1ZXMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnVHhPcmlnaW4gRGV0ZWN0aW9uJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZGV0ZWN0IHR4Lm9yaWdpbiBhdXRoZW50aWNhdGlvbicsICgpID0+IHtcbiAgICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbnByYWdtYSBzb2xpZGl0eSBeMC44LjA7XG5cbmNvbnRyYWN0IFZ1bG5lcmFibGVBdXRoIHtcbiAgICBhZGRyZXNzIG93bmVyO1xuXG4gICAgZnVuY3Rpb24gdHJhbnNmZXIoYWRkcmVzcyB0bywgdWludCBhbW91bnQpIGV4dGVybmFsIHtcbiAgICAgICAgcmVxdWlyZSh0eC5vcmlnaW4gPT0gb3duZXIpO1xuICAgICAgICBwYXlhYmxlKHRvKS50cmFuc2ZlcihhbW91bnQpO1xuICAgIH1cbn1cbmA7XG4gICAgICBjb25zdCB0ZXN0UGF0aCA9IHBhdGguam9pbihfX2Rpcm5hbWUsICd0eG9yaWdpbi10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG4gICAgICAgIGNvbnN0IHR4T3JpZ2luSXNzdWVzID0gcmVzdWx0LnJlc3VsdHMuZmlsdGVyKFxuICAgICAgICAgIHIgPT4gci50eXBlID09PSBWdWxuZXJhYmlsaXR5VHlwZS5UeE9yaWdpblxuICAgICAgICApO1xuICAgICAgICBleHBlY3QodHhPcmlnaW5Jc3N1ZXMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnU2lnbmF0dXJlIE1hbGxlYWJpbGl0eSBEZXRlY3Rpb24nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgZWNyZWNvdmVyIHVzYWdlJywgKCkgPT4ge1xuICAgICAgY29uc3QgdGVzdENvbnRyYWN0ID0gYFxucHJhZ21hIHNvbGlkaXR5IF4wLjguMDtcblxuY29udHJhY3QgU2lnbmF0dXJlVmVyaWZpZXIge1xuICAgIGZ1bmN0aW9uIHZlcmlmeShieXRlczMyIGhhc2gsIHVpbnQ4IHYsIGJ5dGVzMzIgciwgYnl0ZXMzMiBzKSBwdWJsaWMgcHVyZSByZXR1cm5zIChhZGRyZXNzKSB7XG4gICAgICAgIHJldHVybiBlY3JlY292ZXIoaGFzaCwgdiwgciwgcyk7XG4gICAgfVxufVxuYDtcbiAgICAgIGNvbnN0IHRlc3RQYXRoID0gcGF0aC5qb2luKF9fZGlybmFtZSwgJ2VjcmVjb3Zlci10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG4gICAgICAgIGNvbnN0IHNpZ0lzc3VlcyA9IHJlc3VsdC5yZXN1bHRzLmZpbHRlcihcbiAgICAgICAgICByID0+IHIudHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuU2lnbmF0dXJlTWFsbGVhYmlsaXR5XG4gICAgICAgICk7XG4gICAgICAgIGV4cGVjdChzaWdJc3N1ZXMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnSGFyZGNvZGVkIEFkZHJlc3MgRGV0ZWN0aW9uJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZGV0ZWN0IGhhcmRjb2RlZCBhZGRyZXNzZXMnLCAoKSA9PiB7XG4gICAgICBjb25zdCB0ZXN0Q29udHJhY3QgPSBgXG5wcmFnbWEgc29saWRpdHkgXjAuOC4wO1xuXG5jb250cmFjdCBIYXJkY29kZWRBZGRyIHtcbiAgICBmdW5jdGlvbiBzZW5kVG9Pd25lcigpIGV4dGVybmFsIHtcbiAgICAgICAgcGF5YWJsZSgweDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTApLnRyYW5zZmVyKG1zZy52YWx1ZSk7XG4gICAgfVxufVxuYDtcbiAgICAgIGNvbnN0IHRlc3RQYXRoID0gcGF0aC5qb2luKF9fZGlybmFtZSwgJ2hhcmRjb2RlZC10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG4gICAgICAgIGNvbnN0IGhhcmRjb2RlZElzc3VlcyA9IHJlc3VsdC5yZXN1bHRzLmZpbHRlcihcbiAgICAgICAgICByID0+IHIudHlwZSA9PT0gVnVsbmVyYWJpbGl0eVR5cGUuSGFyZGNvZGVkQWRkcmVzc1xuICAgICAgICApO1xuICAgICAgICBleHBlY3QoaGFyZGNvZGVkSXNzdWVzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgaWYgKGZzLmV4aXN0c1N5bmModGVzdFBhdGgpKSB7XG4gICAgICAgICAgZnMudW5saW5rU3luYyh0ZXN0UGF0aCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ01pc3NpbmcgWmVybyBDaGVjayBEZXRlY3Rpb24nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgbWlzc2luZyB6ZXJvIGFkZHJlc3MgdmFsaWRhdGlvbicsICgpID0+IHtcbiAgICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbnByYWdtYSBzb2xpZGl0eSBeMC44LjA7XG5cbmNvbnRyYWN0IFRva2VuVHJhbnNmZXIge1xuICAgIGZ1bmN0aW9uIHRyYW5zZmVyVG8oYWRkcmVzcyByZWNpcGllbnQsIHVpbnQgYW1vdW50KSBleHRlcm5hbCB7XG4gICAgICAgIHJlcXVpcmUoYW1vdW50ID4gMCk7XG4gICAgICAgIC8vIE1pc3NpbmcgemVybyBhZGRyZXNzIGNoZWNrIGZvciByZWNpcGllbnRcbiAgICB9XG59XG5gO1xuICAgICAgY29uc3QgdGVzdFBhdGggPSBwYXRoLmpvaW4oX19kaXJuYW1lLCAnemVyb2NoZWNrLXRlc3Quc29sJyk7XG4gICAgICBmcy53cml0ZUZpbGVTeW5jKHRlc3RQYXRoLCB0ZXN0Q29udHJhY3QpO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBhbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKCk7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IGFuYWx5emVyLmFuYWx5emVGaWxlKHRlc3RQYXRoKTtcbiAgICAgICAgY29uc3QgemVyb0NoZWNrSXNzdWVzID0gcmVzdWx0LnJlc3VsdHMuZmlsdGVyKFxuICAgICAgICAgIHIgPT4gci50eXBlID09PSBWdWxuZXJhYmlsaXR5VHlwZS5NaXNzaW5nWmVyb0NoZWNrXG4gICAgICAgICk7XG4gICAgICAgIGV4cGVjdCh6ZXJvQ2hlY2tJc3N1ZXMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMCk7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnVW5wcm90ZWN0ZWQgSW5pdGlhbGl6ZSBEZXRlY3Rpb24nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgdW5wcm90ZWN0ZWQgaW5pdGlhbGl6ZSBmdW5jdGlvbicsICgpID0+IHtcbiAgICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbnByYWdtYSBzb2xpZGl0eSBeMC44LjA7XG5cbmNvbnRyYWN0IFVwZ3JhZGVhYmxlQ29udHJhY3Qge1xuICAgIGFkZHJlc3MgcHVibGljIG93bmVyO1xuXG4gICAgZnVuY3Rpb24gaW5pdGlhbGl6ZShhZGRyZXNzIF9vd25lcikgZXh0ZXJuYWwge1xuICAgICAgICBvd25lciA9IF9vd25lcjtcbiAgICB9XG59XG5gO1xuICAgICAgY29uc3QgdGVzdFBhdGggPSBwYXRoLmpvaW4oX19kaXJuYW1lLCAnaW5pdGlhbGl6ZS10ZXN0LnNvbCcpO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG4gICAgICAgIGNvbnN0IGluaXRJc3N1ZXMgPSByZXN1bHQucmVzdWx0cy5maWx0ZXIoXG4gICAgICAgICAgciA9PiByLnR5cGUgPT09IFZ1bG5lcmFiaWxpdHlUeXBlLlVucHJvdGVjdGVkSW5pdGlhbGl6ZVxuICAgICAgICApO1xuICAgICAgICBleHBlY3QoaW5pdElzc3Vlcy5sZW5ndGgpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIGlmIChmcy5leGlzdHNTeW5jKHRlc3RQYXRoKSkge1xuICAgICAgICAgIGZzLnVubGlua1N5bmModGVzdFBhdGgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdVbnNhZmUgQ2FzdCBEZXRlY3Rpb24nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBkZXRlY3QgdW5zYWZlIHR5cGUgY2FzdGluZycsICgpID0+IHtcbiAgICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbnByYWdtYSBzb2xpZGl0eSBeMC44LjA7XG5cbmNvbnRyYWN0IFVuc2FmZUNhc3Qge1xuICAgIGZ1bmN0aW9uIGNvbnZlcnQodWludDI1NiB2YWx1ZSkgZXh0ZXJuYWwgcHVyZSByZXR1cm5zICh1aW50OCkge1xuICAgICAgICByZXR1cm4gdWludDgodmFsdWUpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRvQWRkcmVzcyh1aW50MjU2IHZhbCkgZXh0ZXJuYWwgcHVyZSByZXR1cm5zIChhZGRyZXNzKSB7XG4gICAgICAgIHJldHVybiBhZGRyZXNzKHZhbCk7XG4gICAgfVxufVxuYDtcbiAgICAgIGNvbnN0IHRlc3RQYXRoID0gcGF0aC5qb2luKF9fZGlybmFtZSwgJ3Vuc2FmZWNhc3QtdGVzdC5zb2wnKTtcbiAgICAgIGZzLndyaXRlRmlsZVN5bmModGVzdFBhdGgsIHRlc3RDb250cmFjdCk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGFuYWx5emVyID0gY3JlYXRlQW5hbHl6ZXIoKTtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gYW5hbHl6ZXIuYW5hbHl6ZUZpbGUodGVzdFBhdGgpO1xuICAgICAgICBjb25zdCBjYXN0SXNzdWVzID0gcmVzdWx0LnJlc3VsdHMuZmlsdGVyKFxuICAgICAgICAgIHIgPT4gci50eXBlID09PSBWdWxuZXJhYmlsaXR5VHlwZS5VbnNhZmVDYXN0XG4gICAgICAgICk7XG4gICAgICAgIGV4cGVjdChjYXN0SXNzdWVzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgaWYgKGZzLmV4aXN0c1N5bmModGVzdFBhdGgpKSB7XG4gICAgICAgICAgZnMudW5saW5rU3luYyh0ZXN0UGF0aCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfSk7XG59KTtcblxuZGVzY3JpYmUoJ1V0aWxzJywgKCkgPT4ge1xuICBkZXNjcmliZSgncmVhZFNvbGlkaXR5RmlsZScsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIHJlYWQgYSBTb2xpZGl0eSBmaWxlJywgKCkgPT4ge1xuICAgICAgY29uc3QgdGVzdENvbnRlbnQgPSAnY29udHJhY3QgVGVzdCB7fSc7XG4gICAgICBjb25zdCB0ZXN0UGF0aCA9IHBhdGguam9pbihfX2Rpcm5hbWUsICdyZWFkLXRlc3Quc29sJyk7XG4gICAgICBmcy53cml0ZUZpbGVTeW5jKHRlc3RQYXRoLCB0ZXN0Q29udGVudCk7XG5cbiAgICAgIGNvbnN0IHJlc3VsdCA9IHJlYWRTb2xpZGl0eUZpbGUodGVzdFBhdGgpO1xuXG4gICAgICBleHBlY3QocmVzdWx0LnBhdGgpLnRvQmUodGVzdFBhdGgpO1xuICAgICAgZXhwZWN0KHJlc3VsdC5jb250ZW50KS50b0JlKHRlc3RDb250ZW50KTtcbiAgICAgIGV4cGVjdChyZXN1bHQubGluZXMubGVuZ3RoKS50b0JlKDEpO1xuXG4gICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2V4dHJhY3RMaW5lJywgKCkgPT4ge1xuICAgIGNvbnN0IGNvbnRlbnQgPSAnbGluZTFcXG5saW5lMlxcbmxpbmUzJztcblxuICAgIGl0KCdzaG91bGQgZXh0cmFjdCBsaW5lIDEnLCAoKSA9PiB7XG4gICAgICBleHBlY3QoZXh0cmFjdExpbmUoY29udGVudCwgMSkpLnRvQmUoJ2xpbmUxJyk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIGV4dHJhY3QgbGluZSAyJywgKCkgPT4ge1xuICAgICAgZXhwZWN0KGV4dHJhY3RMaW5lKGNvbnRlbnQsIDIpKS50b0JlKCdsaW5lMicpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gZW1wdHkgZm9yIG91dCBvZiBib3VuZHMnLCAoKSA9PiB7XG4gICAgICBleHBlY3QoZXh0cmFjdExpbmUoY29udGVudCwgMTApKS50b0JlKCcnKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2dldFN1cnJvdW5kaW5nTGluZXMnLCAoKSA9PiB7XG4gICAgY29uc3QgY29udGVudCA9ICdsaW5lMVxcbmxpbmUyXFxubGluZTNcXG5saW5lNFxcbmxpbmU1JztcblxuICAgIGl0KCdzaG91bGQgZ2V0IHN1cnJvdW5kaW5nIGxpbmVzJywgKCkgPT4ge1xuICAgICAgY29uc3QgcmVzdWx0ID0gZ2V0U3Vycm91bmRpbmdMaW5lcyhjb250ZW50LCAzLCAxKTtcbiAgICAgIGV4cGVjdChyZXN1bHQuYmVmb3JlKS50b0VxdWFsKFsnbGluZTInXSk7XG4gICAgICBleHBlY3QocmVzdWx0LnRhcmdldCkudG9CZSgnbGluZTMnKTtcbiAgICAgIGV4cGVjdChyZXN1bHQuYWZ0ZXIpLnRvRXF1YWwoWydsaW5lNCddKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2Zvcm1hdFNldmVyaXR5JywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZm9ybWF0IGNyaXRpY2FsIHNldmVyaXR5JywgKCkgPT4ge1xuICAgICAgY29uc3QgZm9ybWF0dGVkID0gZm9ybWF0U2V2ZXJpdHkoU2V2ZXJpdHkuQ3JpdGljYWwpO1xuICAgICAgZXhwZWN0KGZvcm1hdHRlZCkudG9Db250YWluKCdDUklUSUNBTCcpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBmb3JtYXQgaGlnaCBzZXZlcml0eScsICgpID0+IHtcbiAgICAgIGNvbnN0IGZvcm1hdHRlZCA9IGZvcm1hdFNldmVyaXR5KFNldmVyaXR5LkhpZ2gpO1xuICAgICAgZXhwZWN0KGZvcm1hdHRlZCkudG9Db250YWluKCdISUdIJyk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdnZW5lcmF0ZVN1bW1hcnknLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBnZW5lcmF0ZSBzdW1tYXJ5IHdpdGggY29ycmVjdCBjb3VudHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBtb2NrUmVzdWx0cyA9IFtcbiAgICAgICAgeyB0eXBlOiBWdWxuZXJhYmlsaXR5VHlwZS5SZWVudHJhbmN5LCBzZXZlcml0eTogU2V2ZXJpdHkuQ3JpdGljYWwsIG5hbWU6ICdUZXN0JywgZGVzY3JpcHRpb246ICdUZXN0JywgcmVjb21tZW5kYXRpb246ICdUZXN0JywgbGluZTogMSwgY29kZTogJ3Rlc3QnIH0sXG4gICAgICAgIHsgdHlwZTogVnVsbmVyYWJpbGl0eVR5cGUuUmVlbnRyYW5jeSwgc2V2ZXJpdHk6IFNldmVyaXR5LkNyaXRpY2FsLCBuYW1lOiAnVGVzdCcsIGRlc2NyaXB0aW9uOiAnVGVzdCcsIHJlY29tbWVuZGF0aW9uOiAnVGVzdCcsIGxpbmU6IDIsIGNvZGU6ICd0ZXN0JyB9LFxuICAgICAgICB7IHR5cGU6IFZ1bG5lcmFiaWxpdHlUeXBlLkludGVnZXJPdmVyZmxvdywgc2V2ZXJpdHk6IFNldmVyaXR5LkhpZ2gsIG5hbWU6ICdUZXN0JywgZGVzY3JpcHRpb246ICdUZXN0JywgcmVjb21tZW5kYXRpb246ICdUZXN0JywgbGluZTogMywgY29kZTogJ3Rlc3QnIH1cbiAgICAgIF07XG5cbiAgICAgIGNvbnN0IHN1bW1hcnkgPSBnZW5lcmF0ZVN1bW1hcnkobW9ja1Jlc3VsdHMpO1xuXG4gICAgICBleHBlY3Qoc3VtbWFyeS50b3RhbCkudG9CZSgzKTtcbiAgICAgIGV4cGVjdChzdW1tYXJ5LmJ5U2V2ZXJpdHlbU2V2ZXJpdHkuQ3JpdGljYWxdKS50b0JlKDIpO1xuICAgICAgZXhwZWN0KHN1bW1hcnkuYnlTZXZlcml0eVtTZXZlcml0eS5IaWdoXSkudG9CZSgxKTtcbiAgICAgIGV4cGVjdChzdW1tYXJ5LnJpc2tTY29yZSkudG9CZUdyZWF0ZXJUaGFuKDApO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBoYW5kbGUgZW1wdHkgcmVzdWx0cycsICgpID0+IHtcbiAgICAgIGNvbnN0IHN1bW1hcnkgPSBnZW5lcmF0ZVN1bW1hcnkoW10pO1xuICAgICAgZXhwZWN0KHN1bW1hcnkudG90YWwpLnRvQmUoMCk7XG4gICAgICBleHBlY3Qoc3VtbWFyeS5yaXNrU2NvcmUpLnRvQmUoMCk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdpc0NvbW1lbnRMaW5lJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgaWRlbnRpZnkgc2luZ2xlLWxpbmUgY29tbWVudHMnLCAoKSA9PiB7XG4gICAgICBleHBlY3QoaXNDb21tZW50TGluZSgnLy8gVGhpcyBpcyBhIGNvbW1lbnQnKSkudG9CZSh0cnVlKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgaWRlbnRpZnkgbXVsdGktbGluZSBjb21tZW50IHN0YXJ0JywgKCkgPT4ge1xuICAgICAgZXhwZWN0KGlzQ29tbWVudExpbmUoJy8qIFRoaXMgaXMgYSBjb21tZW50JykpLnRvQmUodHJ1ZSk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIGlkZW50aWZ5IG11bHRpLWxpbmUgY29tbWVudCBjb250aW51YXRpb24nLCAoKSA9PiB7XG4gICAgICBleHBlY3QoaXNDb21tZW50TGluZSgnICogVGhpcyBpcyBhIGNvbW1lbnQnKSkudG9CZSh0cnVlKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgcmVqZWN0IG5vbi1jb21tZW50cycsICgpID0+IHtcbiAgICAgIGV4cGVjdChpc0NvbW1lbnRMaW5lKCdjb250cmFjdCBUZXN0IHt9JykpLnRvQmUoZmFsc2UpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZ2V0Q29udHJhY3ROYW1lJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZXh0cmFjdCBjb250cmFjdCBuYW1lJywgKCkgPT4ge1xuICAgICAgY29uc3QgY29udGVudCA9ICdjb250cmFjdCBNeVRva2VuIGlzIEVSQzIwIHsnO1xuICAgICAgZXhwZWN0KGdldENvbnRyYWN0TmFtZShjb250ZW50KSkudG9CZSgnTXlUb2tlbicpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZXR1cm4gbnVsbCBmb3Igbm8gY29udHJhY3QnLCAoKSA9PiB7XG4gICAgICBleHBlY3QoZ2V0Q29udHJhY3ROYW1lKCdqdXN0IHNvbWUgdGV4dCB3aXRob3V0IGtleXdvcmQnKSkudG9CZU51bGwoKTtcbiAgICAgIGV4cGVjdChnZXRDb250cmFjdE5hbWUoJycpKS50b0JlTnVsbCgpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZ2V0UHJhZ21hVmVyc2lvbicsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIGV4dHJhY3QgcHJhZ21hIHZlcnNpb24nLCAoKSA9PiB7XG4gICAgICBjb25zdCBjb250ZW50ID0gJ3ByYWdtYSBzb2xpZGl0eSBeMC44LjA7JztcbiAgICAgIGV4cGVjdChnZXRQcmFnbWFWZXJzaW9uKGNvbnRlbnQpKS50b0JlKCdeMC44LjAnKTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgcmV0dXJuIG51bGwgZm9yIG5vIHByYWdtYScsICgpID0+IHtcbiAgICAgIGV4cGVjdChnZXRQcmFnbWFWZXJzaW9uKCdubyBwcmFnbWEgaGVyZScpKS50b0JlTnVsbCgpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnbm9ybWFsaXplV2hpdGVzcGFjZScsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIG5vcm1hbGl6ZSBtdWx0aXBsZSBzcGFjZXMnLCAoKSA9PiB7XG4gICAgICBleHBlY3Qobm9ybWFsaXplV2hpdGVzcGFjZSgnYSAgIGIgICAgYycpKS50b0JlKCdhIGIgYycpO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCB0cmltIHdoaXRlc3BhY2UnLCAoKSA9PiB7XG4gICAgICBleHBlY3Qobm9ybWFsaXplV2hpdGVzcGFjZSgnICB0ZXN0ICAnKSkudG9CZSgndGVzdCcpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZmlsdGVyQ29tbWVudHMnLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBmaWx0ZXIgb3V0IGNvbW1lbnQgbGluZXMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBsaW5lcyA9IFsnLy8gY29tbWVudCcsICdjb2RlJywgJy8qIGNvbW1lbnQnLCAnbW9yZSBjb2RlJ107XG4gICAgICBjb25zdCBmaWx0ZXJlZCA9IGZpbHRlckNvbW1lbnRzKGxpbmVzKTtcbiAgICAgIGV4cGVjdChmaWx0ZXJlZCkudG9FcXVhbChbJ2NvZGUnLCAnbW9yZSBjb2RlJ10pO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZmluZFN0YXRlVmFyaWFibGVzJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZmluZCBzdGF0ZSB2YXJpYWJsZXMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYFxuICAgICAgICBjb250cmFjdCBUZXN0IHtcbiAgICAgICAgICAgIHVpbnQyNTYgcHVibGljIGJhbGFuY2U7XG4gICAgICAgICAgICBhZGRyZXNzIG93bmVyO1xuICAgICAgICAgICAgbWFwcGluZyhhZGRyZXNzID0+IHVpbnQpIGJhbGFuY2VzO1xuICAgICAgICB9XG4gICAgICBgO1xuICAgICAgY29uc3QgdmFycyA9IGZpbmRTdGF0ZVZhcmlhYmxlcyhjb250ZW50KTtcbiAgICAgIGV4cGVjdCh2YXJzKS50b0NvbnRhaW4oJ293bmVyJyk7XG4gICAgICBleHBlY3QodmFycykudG9Db250YWluKCdiYWxhbmNlcycpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZmluZEZ1bmN0aW9ucycsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIGZpbmQgZnVuY3Rpb25zIHdpdGggbWV0YWRhdGEnLCAoKSA9PiB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYFxuICAgICAgICBjb250cmFjdCBUZXN0IHtcbiAgICAgICAgICAgIGZ1bmN0aW9uIHRlc3RGdW5jKHVpbnQgYSkgZXh0ZXJuYWwgcHVyZSByZXR1cm5zICh1aW50KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGE7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIGA7XG4gICAgICBjb25zdCBmdW5jdGlvbnMgPSBmaW5kRnVuY3Rpb25zKGNvbnRlbnQpO1xuICAgICAgZXhwZWN0KGZ1bmN0aW9ucy5sZW5ndGgpLnRvQmVHcmVhdGVyVGhhbigwKTtcbiAgICAgIGV4cGVjdChmdW5jdGlvbnNbMF0ubmFtZSkudG9CZSgndGVzdEZ1bmMnKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2ZpbmRFdmVudHMnLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBmaW5kIGV2ZW50IGRlZmluaXRpb25zJywgKCkgPT4ge1xuICAgICAgY29uc3QgY29udGVudCA9IGBcbiAgICAgICAgY29udHJhY3QgVGVzdCB7XG4gICAgICAgICAgICBldmVudCBUcmFuc2ZlcihhZGRyZXNzIGluZGV4ZWQgZnJvbSwgYWRkcmVzcyBpbmRleGVkIHRvKTtcbiAgICAgICAgICAgIGV2ZW50IEFwcHJvdmFsKGFkZHJlc3MgaW5kZXhlZCBvd25lciwgYWRkcmVzcyBpbmRleGVkIHNwZW5kZXIpO1xuICAgICAgICB9XG4gICAgICBgO1xuICAgICAgY29uc3QgZXZlbnRzID0gZmluZEV2ZW50cyhjb250ZW50KTtcbiAgICAgIGV4cGVjdChldmVudHMpLnRvQ29udGFpbignVHJhbnNmZXInKTtcbiAgICAgIGV4cGVjdChldmVudHMpLnRvQ29udGFpbignQXBwcm92YWwnKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2ZpbmRNb2RpZmllcnMnLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBmaW5kIG1vZGlmaWVyIGRlZmluaXRpb25zJywgKCkgPT4ge1xuICAgICAgY29uc3QgY29udGVudCA9IGBcbiAgICAgICAgY29udHJhY3QgVGVzdCB7XG4gICAgICAgICAgICBtb2RpZmllciBvbmx5T3duZXIoKSB7IF87IH1cbiAgICAgICAgICAgIG1vZGlmaWVyIHdoZW5Ob3RQYXVzZWQoKSB7IF87IH1cbiAgICAgICAgfVxuICAgICAgYDtcbiAgICAgIGNvbnN0IG1vZGlmaWVycyA9IGZpbmRNb2RpZmllcnMoY29udGVudCk7XG4gICAgICBleHBlY3QobW9kaWZpZXJzKS50b0NvbnRhaW4oJ29ubHlPd25lcicpO1xuICAgICAgZXhwZWN0KG1vZGlmaWVycykudG9Db250YWluKCd3aGVuTm90UGF1c2VkJyk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdjb3VudExpbmVzJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgY291bnQgbGluZXMgY29ycmVjdGx5JywgKCkgPT4ge1xuICAgICAgY29uc3QgY29udGVudCA9IGBsaW5lMVxuLy8gY29tbWVudFxubGluZTNcblxubGluZTVgO1xuICAgICAgY29uc3QgY291bnRzID0gY291bnRMaW5lcyhjb250ZW50KTtcbiAgICAgIGV4cGVjdChjb3VudHMudG90YWwpLnRvQmUoNSk7XG4gICAgICBleHBlY3QoY291bnRzLmNvbW1lbnRzKS50b0JlKDEpO1xuICAgICAgZXhwZWN0KGNvdW50cy5ibGFuaykudG9CZSgxKTtcbiAgICAgIGV4cGVjdChjb3VudHMuY29kZSkudG9CZSgzKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ2dldEluaGVyaXRhbmNlQ2hhaW4nLCAoKSA9PiB7XG4gICAgaXQoJ3Nob3VsZCBleHRyYWN0IGluaGVyaXRhbmNlIGNoYWluJywgKCkgPT4ge1xuICAgICAgY29uc3QgY29udGVudCA9ICdjb250cmFjdCBNeVRva2VuIGlzIEVSQzIwLCBPd25hYmxlIHsnO1xuICAgICAgY29uc3QgY2hhaW4gPSBnZXRJbmhlcml0YW5jZUNoYWluKGNvbnRlbnQpO1xuICAgICAgZXhwZWN0KGNoYWluKS50b0NvbnRhaW4oJ0VSQzIwJyk7XG4gICAgICBleHBlY3QoY2hhaW4pLnRvQ29udGFpbignT3duYWJsZScpO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnaXNVcGdyYWRlYWJsZScsICgpID0+IHtcbiAgICBpdCgnc2hvdWxkIGRldGVjdCB1cGdyYWRlYWJsZSBjb250cmFjdHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYFxuICAgICAgICBjb250cmFjdCBVcGdyYWRlYWJsZUNvbnRyYWN0IGlzIEluaXRpYWxpemFibGUge1xuICAgICAgICAgICAgZnVuY3Rpb24gaW5pdGlhbGl6ZSgpIHB1YmxpYyBpbml0aWFsaXplciB7fVxuICAgICAgICB9XG4gICAgICBgO1xuICAgICAgZXhwZWN0KGlzVXBncmFkZWFibGUoY29udGVudCkpLnRvQmUodHJ1ZSk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIHJldHVybiBmYWxzZSBmb3Igbm9uLXVwZ3JhZGVhYmxlIGNvbnRyYWN0cycsICgpID0+IHtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSAnY29udHJhY3QgU2ltcGxlQ29udHJhY3Qge30nO1xuICAgICAgZXhwZWN0KGlzVXBncmFkZWFibGUoY29udGVudCkpLnRvQmUoZmFsc2UpO1xuICAgIH0pO1xuICB9KTtcbn0pO1xuXG5kZXNjcmliZSgnSW50ZWdyYXRpb24gVGVzdHMnLCAoKSA9PiB7XG4gIGl0KCdzaG91bGQgcGVyZm9ybSBmdWxsIGFuYWx5c2lzIHdvcmtmbG93JywgKCkgPT4ge1xuICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbi8vIFNQRFgtTGljZW5zZS1JZGVudGlmaWVyOiBNSVRcbnByYWdtYSBzb2xpZGl0eSBeMC43LjA7XG5cbmNvbnRyYWN0IFNhZmVDb250cmFjdCB7XG4gICAgbWFwcGluZyhhZGRyZXNzID0+IHVpbnQpIHByaXZhdGUgYmFsYW5jZXM7XG5cbiAgICBmdW5jdGlvbiBkZXBvc2l0KCkgZXh0ZXJuYWwgcGF5YWJsZSB7XG4gICAgICAgIGJhbGFuY2VzW21zZy5zZW5kZXJdICs9IG1zZy52YWx1ZTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB3aXRoZHJhdyh1aW50IGFtb3VudCkgZXh0ZXJuYWwge1xuICAgICAgICByZXF1aXJlKGJhbGFuY2VzW21zZy5zZW5kZXJdID49IGFtb3VudCwgXCJJbnN1ZmZpY2llbnQgYmFsYW5jZVwiKTtcbiAgICAgICAgYmFsYW5jZXNbbXNnLnNlbmRlcl0gLT0gYW1vdW50O1xuICAgICAgICAoYm9vbCBzdWNjZXNzLCApID0gcGF5YWJsZShtc2cuc2VuZGVyKS5jYWxse3ZhbHVlOiBhbW91bnR9KFwiXCIpO1xuICAgICAgICByZXF1aXJlKHN1Y2Nlc3MsIFwiVHJhbnNmZXIgZmFpbGVkXCIpO1xuICAgIH1cbn1cbmA7XG5cbiAgICBjb25zdCB0ZXN0UGF0aCA9IHBhdGguam9pbihfX2Rpcm5hbWUsICdzYWZlLWNvbnRyYWN0LnNvbCcpO1xuICAgIGZzLndyaXRlRmlsZVN5bmModGVzdFBhdGgsIHRlc3RDb250cmFjdCk7XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgYW5hbHl6ZXIgPSBjcmVhdGVBbmFseXplcigpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gYW5hbHl6ZXIuYW5hbHl6ZUZpbGUodGVzdFBhdGgpO1xuXG4gICAgICBleHBlY3QocmVzdWx0LmNvbnRyYWN0TmFtZSkudG9CZSgnU2FmZUNvbnRyYWN0Jyk7XG4gICAgICBleHBlY3QocmVzdWx0LnByYWdtYVZlcnNpb24pLnRvQmUoJ14wLjcuMCcpO1xuICAgIH0gZmluYWxseSB7XG4gICAgICBpZiAoZnMuZXhpc3RzU3luYyh0ZXN0UGF0aCkpIHtcbiAgICAgICAgZnMudW5saW5rU3luYyh0ZXN0UGF0aCk7XG4gICAgICB9XG4gICAgfVxuICB9KTtcblxuICBpdCgnc2hvdWxkIGFuYWx5emUgY29tcHJlaGVuc2l2ZSB2dWxuZXJhYmxlIGNvbnRyYWN0JywgKCkgPT4ge1xuICAgIGNvbnN0IHRlc3RDb250cmFjdCA9IGBcbi8vIFNQRFgtTGljZW5zZS1JZGVudGlmaWVyOiBNSVRcbnByYWdtYSBzb2xpZGl0eSBeMC43LjA7XG5cbmNvbnRyYWN0IENvbXByZWhlbnNpdmVWdWxuZXJhYmxlIHtcbiAgICBhZGRyZXNzIHB1YmxpYyBvd25lcjtcbiAgICB1aW50MjU2IHB1YmxpYyBiYWxhbmNlO1xuICAgIGFkZHJlc3MgcHVibGljIGltcGxlbWVudGF0aW9uO1xuXG4gICAgZXZlbnQgRGVwb3NpdChhZGRyZXNzIGluZGV4ZWQgdXNlciwgdWludDI1NiBhbW91bnQpO1xuXG4gICAgZnVuY3Rpb24gZGVwb3NpdCgpIGV4dGVybmFsIHBheWFibGUge1xuICAgICAgICBiYWxhbmNlICs9IG1zZy52YWx1ZTtcbiAgICAgICAgZW1pdCBEZXBvc2l0KG1zZy5zZW5kZXIsIG1zZy52YWx1ZSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gd2l0aGRyYXcodWludDI1NiBhbW91bnQpIGV4dGVybmFsIHtcbiAgICAgICAgcmVxdWlyZSh0eC5vcmlnaW4gPT0gb3duZXIpO1xuICAgICAgICAoYm9vbCBzdWNjZXNzLCApID0gbXNnLnNlbmRlci5jYWxse3ZhbHVlOiBhbW91bnR9KFwiXCIpO1xuICAgICAgICBiYWxhbmNlIC09IGFtb3VudDtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB1cGdyYWRlKGFkZHJlc3MgbmV3SW1wbCkgZXh0ZXJuYWwge1xuICAgICAgICBpbXBsZW1lbnRhdGlvbiA9IG5ld0ltcGw7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZXhlY3V0ZShieXRlcyBjYWxsZGF0YSBkYXRhKSBleHRlcm5hbCB7XG4gICAgICAgIChib29sIHN1Y2Nlc3MsICkgPSBpbXBsZW1lbnRhdGlvbi5kZWxlZ2F0ZWNhbGwoZGF0YSk7XG4gICAgICAgIHJlcXVpcmUoc3VjY2Vzcyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0UmFuZG9tKCkgZXh0ZXJuYWwgdmlldyByZXR1cm5zICh1aW50MjU2KSB7XG4gICAgICAgIHJldHVybiB1aW50MjU2KGtlY2NhazI1NihhYmkuZW5jb2RlUGFja2VkKGJsb2NrLnRpbWVzdGFtcCwgYmxvY2suZGlmZmljdWx0eSkpKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0cmFuc2ZlclRvKGFkZHJlc3MgcmVjaXBpZW50LCB1aW50MjU2IGFtb3VudCkgZXh0ZXJuYWwge1xuICAgICAgICBwYXlhYmxlKDB4MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MCkudHJhbnNmZXIoYW1vdW50KTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBraWxsKCkgZXh0ZXJuYWwge1xuICAgICAgICBzZWxmZGVzdHJ1Y3QocGF5YWJsZShvd25lcikpO1xuICAgIH1cbn1cbmA7XG5cbiAgICBjb25zdCB0ZXN0UGF0aCA9IHBhdGguam9pbihfX2Rpcm5hbWUsICdjb21wcmVoZW5zaXZlLXRlc3Quc29sJyk7XG4gICAgZnMud3JpdGVGaWxlU3luYyh0ZXN0UGF0aCwgdGVzdENvbnRyYWN0KTtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBhbmFseXplciA9IGNyZWF0ZUFuYWx5emVyKCk7XG4gICAgICBjb25zdCByZXN1bHQgPSBhbmFseXplci5hbmFseXplRmlsZSh0ZXN0UGF0aCk7XG5cbiAgICAgIGV4cGVjdChyZXN1bHQuY29udHJhY3ROYW1lKS50b0JlKCdDb21wcmVoZW5zaXZlVnVsbmVyYWJsZScpO1xuICAgICAgZXhwZWN0KHJlc3VsdC5yZXN1bHRzLmxlbmd0aCkudG9CZUdyZWF0ZXJUaGFuKDUpO1xuXG4gICAgICBjb25zdCB0eXBlcyA9IHJlc3VsdC5yZXN1bHRzLm1hcChyID0+IHIudHlwZSk7XG4gICAgICBleHBlY3QodHlwZXMpLnRvQ29udGFpbihWdWxuZXJhYmlsaXR5VHlwZS5UeE9yaWdpbik7XG4gICAgICBleHBlY3QodHlwZXMpLnRvQ29udGFpbihWdWxuZXJhYmlsaXR5VHlwZS5EZWxlZ2F0ZUNhbGwpO1xuICAgICAgZXhwZWN0KHR5cGVzKS50b0NvbnRhaW4oVnVsbmVyYWJpbGl0eVR5cGUuV2Vha1JhbmRvbW5lc3MpO1xuICAgICAgZXhwZWN0KHR5cGVzKS50b0NvbnRhaW4oVnVsbmVyYWJpbGl0eVR5cGUuSGFyZGNvZGVkQWRkcmVzcyk7XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgIGlmIChmcy5leGlzdHNTeW5jKHRlc3RQYXRoKSkge1xuICAgICAgICBmcy51bmxpbmtTeW5jKHRlc3RQYXRoKTtcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSk7XG4iXX0=