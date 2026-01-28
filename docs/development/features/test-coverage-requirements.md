# Test Coverage Requirements Specification

## Document Information

| Field | Value |
|-------|-------|
| **Version** | 1.0.0 |
| **Status** | Draft |
| **Created** | 2026-01-28 |
| **Author** | QA & DevOps Engineer |
| **Component** | Testing Framework |

---

## Table of Contents

1. [Coverage Philosophy](#1-coverage-philosophy)
2. [Coverage Targets by Module](#2-coverage-targets-by-module)
3. [Coverage Types](#3-coverage-types)
4. [Exclusion Rules](#4-exclusion-rules)
5. [CI Enforcement Configuration](#5-ci-enforcement-configuration)
6. [Coverage Reporting Tools](#6-coverage-reporting-tools)
7. [Coverage Trend Tracking](#7-coverage-trend-tracking)
8. [Remediation Process](#8-remediation-process)
9. [Appendix](#appendix)

---

## 1. Coverage Philosophy

### 1.1 Core Principles

Test coverage for the XRPL Agent Wallet MCP server follows a **risk-weighted approach** where coverage requirements are proportional to the security criticality and complexity of each module.

| Principle | Description |
|-----------|-------------|
| **Security-First Coverage** | Modules handling cryptographic operations, key management, and policy enforcement require the highest coverage |
| **Quality Over Quantity** | 100% coverage is not the goal; meaningful coverage of critical paths takes precedence |
| **Branch Coverage Priority** | Branch coverage is prioritized over line coverage for decision-making code |
| **Mutation Testing Validation** | Coverage metrics are validated through mutation testing to ensure test quality |
| **Continuous Enforcement** | Coverage requirements are enforced on every commit via CI/CD pipeline |
| **Regression Prevention** | Every bug fix must include a regression test before closing |

### 1.2 Coverage Pyramid

```
                    ┌─────────────────────┐
                    │     95%+ Coverage    │  Security-Critical
                    │   (keystore, policy, │  Modules
                    │    signing, validators)│
                    └─────────────────────┘
                   ┌───────────────────────┐
                   │      90% Coverage      │  Core Infrastructure
                   │       (audit)          │  Modules
                   └───────────────────────┘
              ┌─────────────────────────────────┐
              │         85% Coverage            │  Integration
              │       (xrpl, mcp)               │  Modules
              └─────────────────────────────────┘
         ┌───────────────────────────────────────────┐
         │             80% Minimum                    │  Utility &
         │        (utils, types, helpers)             │  Support Code
         └───────────────────────────────────────────┘
```

### 1.3 Why These Thresholds?

| Threshold | Rationale |
|-----------|-----------|
| **95%** | Security-critical modules where any uncovered code path could lead to key exposure, unauthorized transactions, or policy bypass |
| **90%** | Infrastructure modules where comprehensive coverage ensures audit trail integrity and system observability |
| **85%** | Integration modules where external dependencies (XRPL network, MCP protocol) introduce testing complexity |
| **80%** | Support code where diminishing returns make higher coverage cost-prohibitive |

---

## 2. Coverage Targets by Module

### 2.1 Security-Critical Modules (95% Required)

These modules handle cryptographic operations, key management, and authorization. Any gap in coverage represents a potential security vulnerability.

#### src/keystore/ (95%)

```yaml
# Coverage requirements for keystore module
module: src/keystore/
minimum_coverage:
  line: 95%
  branch: 95%
  function: 95%
  statement: 95%

critical_paths:
  - Key generation (entropy, algorithm selection)
  - Key storage (encryption at rest)
  - Key retrieval (decryption, access control)
  - Key deletion (secure wiping)
  - Key rotation (atomic swap)
  - Password derivation (Argon2id parameters)

mandatory_test_types:
  - Unit tests for all encryption/decryption paths
  - Property-based tests for key generation
  - Memory safety tests for key handling
  - Error path tests for all failure modes

justification: |
  The keystore module protects private keys that control real financial assets.
  Any uncovered code path could lead to key exposure (T-002, I-001, I-002)
  or loss of funds. 95% coverage ensures all cryptographic operations
  are thoroughly tested.
```

#### src/policy/ (95%)

```yaml
# Coverage requirements for policy module
module: src/policy/
minimum_coverage:
  line: 95%
  branch: 95%
  function: 95%
  statement: 95%

critical_paths:
  - Tier evaluation (1-4 classification)
  - Limit enforcement (amount, daily, hourly)
  - Allowlist/blocklist checking
  - Time-window validation
  - Multi-signature requirements
  - Policy composition and merging

mandatory_test_types:
  - Boundary value tests for all thresholds
  - Policy bypass attempt tests
  - Combination tests for multiple constraints
  - Time-based policy tests with mocked clock
  - Fuzz tests for policy evaluation

justification: |
  The policy engine is the primary defense against unauthorized transactions.
  Uncovered branches in policy evaluation could allow attackers to bypass
  spending limits (T-003, E-002) or execute prohibited transactions.
```

#### src/signing/ (95%)

```yaml
# Coverage requirements for signing module
module: src/signing/
minimum_coverage:
  line: 95%
  branch: 95%
  function: 95%
  statement: 95%

critical_paths:
  - Transaction signing (single-sig)
  - Multi-signature coordination
  - Signature verification
  - Transaction serialization
  - Signing key retrieval
  - Signature aggregation

mandatory_test_types:
  - Cryptographic correctness tests
  - Multi-signature workflow tests
  - Invalid transaction rejection tests
  - Malformed input tests
  - Replay attack prevention tests

justification: |
  The signing service creates cryptographic signatures that authorize
  real financial transactions. Any uncovered path could lead to invalid
  signatures, transaction malleability, or signing unauthorized transactions.
```

#### src/validators/ (95%)

```yaml
# Coverage requirements for validators module
module: src/validators/
minimum_coverage:
  line: 95%
  branch: 95%
  function: 95%
  statement: 95%

critical_paths:
  - Input sanitization (all MCP inputs)
  - Prompt injection detection
  - XRPL address validation
  - Amount validation (drops, overflow)
  - Transaction structure validation
  - Memo content validation

mandatory_test_types:
  - Prompt injection payload tests
  - Fuzzing with malformed inputs
  - Unicode normalization tests
  - Encoding bypass tests (Base64, hex)
  - Edge case boundary tests

justification: |
  Input validation is the first line of defense against prompt injection
  attacks (T-001, CRITICAL) and malformed input attacks. Every validation
  function must be thoroughly tested with adversarial inputs.
```

### 2.2 Core Infrastructure Modules (90% Required)

#### src/audit/ (90%)

```yaml
# Coverage requirements for audit module
module: src/audit/
minimum_coverage:
  line: 90%
  branch: 90%
  function: 90%
  statement: 90%

critical_paths:
  - Event logging (all event types)
  - Hash chain construction
  - Hash chain verification
  - HMAC computation
  - Query and filtering
  - Log rotation and archival

mandatory_test_types:
  - Chain integrity tests
  - Tamper detection tests
  - Concurrent write tests
  - Recovery from corruption tests
  - Query performance tests

justification: |
  The audit logger provides forensic evidence for security investigations
  and compliance. Hash chain integrity must be maintained to ensure
  tamper-evident logging (AUDIT-001 to AUDIT-006).
```

### 2.3 Integration Modules (85% Required)

#### src/xrpl/ (85%)

```yaml
# Coverage requirements for XRPL module
module: src/xrpl/
minimum_coverage:
  line: 85%
  branch: 85%
  function: 85%
  statement: 85%

critical_paths:
  - Connection management
  - Transaction submission
  - Account info queries
  - Transaction verification
  - Error handling (network failures)
  - Reconnection logic

mandatory_test_types:
  - Mock-based unit tests
  - Integration tests with testnet
  - Network failure simulation tests
  - Timeout and retry tests
  - Rate limiting tests

justification: |
  The XRPL client integrates with external network infrastructure where
  some code paths depend on network conditions that are difficult to
  reproduce deterministically. 85% coverage with comprehensive error
  path testing provides adequate assurance.
```

#### src/mcp/ (85%)

```yaml
# Coverage requirements for MCP module
module: src/mcp/
minimum_coverage:
  line: 85%
  branch: 85%
  function: 85%
  statement: 85%

critical_paths:
  - Tool registration
  - Request routing
  - Response formatting
  - Error handling
  - Protocol compliance
  - Server lifecycle

mandatory_test_types:
  - Protocol conformance tests
  - Tool invocation tests
  - Error response tests
  - Concurrent request tests
  - Resource cleanup tests

justification: |
  The MCP server layer handles protocol-level concerns where some
  edge cases depend on client behavior. 85% coverage ensures core
  functionality is tested while acknowledging protocol complexity.
```

### 2.4 Overall Project Coverage (90% Required)

```yaml
# Overall project coverage requirements
project: xrpl-wallet-mcp
minimum_coverage:
  line: 90%
  branch: 85%
  function: 90%
  statement: 90%

calculation: |
  Overall coverage is calculated as weighted average:
  - Security-critical modules (keystore, policy, signing, validators): 40% weight
  - Core infrastructure (audit): 20% weight
  - Integration modules (xrpl, mcp): 25% weight
  - Utility code: 15% weight
```

### 2.5 Coverage Target Summary Table

| Module | Line | Branch | Function | Statement | Priority |
|--------|------|--------|----------|-----------|----------|
| `src/keystore/` | 95% | 95% | 95% | 95% | Critical |
| `src/policy/` | 95% | 95% | 95% | 95% | Critical |
| `src/signing/` | 95% | 95% | 95% | 95% | Critical |
| `src/validators/` | 95% | 95% | 95% | 95% | Critical |
| `src/audit/` | 90% | 90% | 90% | 90% | High |
| `src/xrpl/` | 85% | 85% | 85% | 85% | Medium |
| `src/mcp/` | 85% | 85% | 85% | 85% | Medium |
| **Overall** | **90%** | **85%** | **90%** | **90%** | - |

---

## 3. Coverage Types

### 3.1 Line Coverage

**Definition:** Percentage of executable source code lines that have been executed during testing.

```typescript
// Example: Line coverage tracking
function calculateTier(amount: number): number {
  if (amount <= TIER_1_LIMIT) {        // Line 1: Covered
    return 1;                           // Line 2: Covered
  } else if (amount <= TIER_2_LIMIT) { // Line 3: Covered
    return 2;                           // Line 4: Covered
  } else if (amount <= TIER_3_LIMIT) { // Line 5: Needs test
    return 3;                           // Line 6: Needs test
  } else {                              // Line 7: Needs test
    return 4;                           // Line 8: Needs test
  }
}
// Line coverage: 4/8 = 50%
```

**Requirements:**
- Security-critical modules: 95% line coverage minimum
- All error handling paths must be exercised
- No dead code (0% covered lines indicate potential issues)

### 3.2 Branch Coverage

**Definition:** Percentage of decision branches (if/else, switch cases, ternary operators) that have been executed.

```typescript
// Example: Branch coverage tracking
function validateAmount(amount: number): ValidationResult {
  // Branch 1: amount <= 0
  // Branch 2: amount > 0
  if (amount <= 0) {
    return { valid: false, error: 'INVALID_AMOUNT' };
  }

  // Branch 3: amount > MAX_AMOUNT
  // Branch 4: amount <= MAX_AMOUNT
  if (amount > MAX_AMOUNT) {
    return { valid: false, error: 'AMOUNT_EXCEEDS_MAXIMUM' };
  }

  return { valid: true };
}
// To achieve 100% branch coverage, tests must cover:
// - amount = -1 (branch 1)
// - amount = 100 (branch 2, branch 4)
// - amount = MAX_AMOUNT + 1 (branch 3)
```

**Requirements:**
- Branch coverage is prioritized for decision-making code
- All policy evaluation branches must be tested
- Boolean expressions must test both true and false outcomes

### 3.3 Function Coverage

**Definition:** Percentage of functions that have been called during testing.

```typescript
// Function coverage ensures all exported functions are tested
export function createWallet(): WalletResult { ... }      // Must be tested
export function deleteWallet(id: string): void { ... }   // Must be tested
export function rotateKey(id: string): void { ... }      // Must be tested

// Internal helper functions
function deriveKey(password: string): Buffer { ... }     // Must be tested
function encryptData(data: Buffer, key: Buffer): Buffer { ... } // Must be tested
```

**Requirements:**
- All public API functions must have at least one test
- Internal functions critical to security must be tested
- Unused functions (0% coverage) should be removed

### 3.4 Statement Coverage

**Definition:** Percentage of executable statements that have been executed.

**Requirements:**
- Statement coverage provides the baseline metric
- Often similar to line coverage but accounts for multi-statement lines
- Required for comprehensive coverage reporting

### 3.5 Coverage Type Priority

For security-critical code, the priority order is:

1. **Branch Coverage** - Ensures all decision paths are tested
2. **Line Coverage** - Ensures all code is exercised
3. **Function Coverage** - Ensures all entry points are tested
4. **Statement Coverage** - Provides baseline verification

---

## 4. Exclusion Rules

### 4.1 Standard Exclusions

The following patterns are excluded from coverage calculation:

```typescript
// vitest.config.ts coverage exclusions
export default defineConfig({
  test: {
    coverage: {
      exclude: [
        // Type definitions (no runtime code)
        'src/**/*.d.ts',
        'src/types/**',

        // Test files themselves
        'tests/**',
        '**/*.test.ts',
        '**/*.spec.ts',

        // Test fixtures and mocks
        'tests/fixtures/**',
        'tests/mocks/**',

        // Generated code
        'src/**/*.generated.ts',
        'dist/**',

        // Configuration files
        '*.config.ts',
        '*.config.js',

        // Development tools
        'scripts/**',
        'tools/**',

        // Documentation examples
        'examples/**',
        'docs/**',

        // Node modules
        'node_modules/**',
      ],
    },
  },
});
```

### 4.2 Inline Exclusions

Use inline comments sparingly for legitimate exclusions:

```typescript
// Exclusion: Debug-only code
/* istanbul ignore if */
if (process.env.NODE_ENV === 'development') {
  console.debug('Debug info:', debugData);
}

// Exclusion: Unreachable code for type narrowing
/* istanbul ignore next */
function assertNever(x: never): never {
  throw new Error('Unexpected value: ' + x);
}

// Exclusion: Platform-specific code tested separately
/* istanbul ignore else */
if (process.platform === 'win32') {
  // Windows-specific implementation
} else {
  // Unix implementation (primary test target)
}
```

### 4.3 Exclusion Justification Requirements

All inline exclusions must include a justification:

```typescript
// ALLOWED: Clear justification
/* istanbul ignore if -- @preserve Debug logging not tested */
if (DEBUG_MODE) { ... }

// NOT ALLOWED: No justification
/* istanbul ignore if */
if (someCondition) { ... }
```

### 4.4 Exclusion Categories

| Category | Allowed | Example |
|----------|---------|---------|
| Debug/logging code | Yes | `console.debug()` statements |
| Type assertions | Yes | TypeScript type narrowing |
| Platform-specific | Yes | OS-specific code paths |
| Error boundaries | Conditional | Must test primary path |
| Generated code | Yes | Auto-generated files |
| Test utilities | Yes | Test helper functions |
| Security-critical | **No** | Never exclude security code |

### 4.5 Monitoring Exclusion Usage

```yaml
# CI check for exclusion abuse
coverage_exclusion_audit:
  max_inline_excludes: 20
  max_per_file: 3
  forbidden_in_modules:
    - src/keystore/
    - src/policy/
    - src/signing/
    - src/validators/
  alert_on_increase: true
```

---

## 5. CI Enforcement Configuration

### 5.1 Vitest Coverage Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',

      // Reporters for different purposes
      reporter: [
        'text',           // Console output
        'text-summary',   // CI summary
        'json',           // Machine-readable
        'json-summary',   // Condensed JSON
        'html',           // Visual report
        'lcov',           // For codecov/sonarqube
        'cobertura',      // For Azure DevOps
      ],

      // Output directories
      reportsDirectory: './coverage',

      // What to include
      include: ['src/**/*.ts'],

      // Global thresholds (fail CI if not met)
      thresholds: {
        // Overall project thresholds
        lines: 90,
        branches: 85,
        functions: 90,
        statements: 90,

        // Per-file thresholds (stricter for security modules)
        perFile: true,

        // Auto-update thresholds (ratcheting)
        autoUpdate: false,
      },

      // Fail if coverage decreases
      all: true,
      skipFull: false,

      // Clean coverage before run
      clean: true,

      // Additional options
      ignoreEmptyLines: true,
      processingConcurrency: 4,
    },
  },
});
```

### 5.2 Module-Specific Thresholds

```typescript
// vitest.config.ts - Module-specific thresholds
export default defineConfig({
  test: {
    coverage: {
      thresholds: {
        // Security-critical modules (95%)
        'src/keystore/**': {
          lines: 95,
          branches: 95,
          functions: 95,
          statements: 95,
        },
        'src/policy/**': {
          lines: 95,
          branches: 95,
          functions: 95,
          statements: 95,
        },
        'src/signing/**': {
          lines: 95,
          branches: 95,
          functions: 95,
          statements: 95,
        },
        'src/validators/**': {
          lines: 95,
          branches: 95,
          functions: 95,
          statements: 95,
        },

        // Core infrastructure (90%)
        'src/audit/**': {
          lines: 90,
          branches: 90,
          functions: 90,
          statements: 90,
        },

        // Integration modules (85%)
        'src/xrpl/**': {
          lines: 85,
          branches: 85,
          functions: 85,
          statements: 85,
        },
        'src/mcp/**': {
          lines: 85,
          branches: 85,
          functions: 85,
          statements: 85,
        },
      },
    },
  },
});
```

### 5.3 GitHub Actions Workflow

```yaml
# .github/workflows/coverage.yml
name: Test Coverage

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  coverage:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests with coverage
        run: npm run test:coverage
        env:
          CI: true

      - name: Check coverage thresholds
        run: |
          # Extract coverage summary
          COVERAGE=$(cat coverage/coverage-summary.json)

          # Check overall thresholds
          LINES=$(echo $COVERAGE | jq '.total.lines.pct')
          BRANCHES=$(echo $COVERAGE | jq '.total.branches.pct')
          FUNCTIONS=$(echo $COVERAGE | jq '.total.functions.pct')

          echo "Line coverage: $LINES%"
          echo "Branch coverage: $BRANCHES%"
          echo "Function coverage: $FUNCTIONS%"

          # Fail if below thresholds
          if (( $(echo "$LINES < 90" | bc -l) )); then
            echo "Line coverage ($LINES%) is below threshold (90%)"
            exit 1
          fi

          if (( $(echo "$BRANCHES < 85" | bc -l) )); then
            echo "Branch coverage ($BRANCHES%) is below threshold (85%)"
            exit 1
          fi

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          files: ./coverage/lcov.info
          flags: unittests
          name: codecov-umbrella
          fail_ci_if_error: true

      - name: Post coverage comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = JSON.parse(fs.readFileSync('coverage/coverage-summary.json', 'utf8'));

            const total = summary.total;
            const comment = `## Coverage Report

            | Metric | Coverage | Threshold | Status |
            |--------|----------|-----------|--------|
            | Lines | ${total.lines.pct.toFixed(2)}% | 90% | ${total.lines.pct >= 90 ? ':white_check_mark:' : ':x:'} |
            | Branches | ${total.branches.pct.toFixed(2)}% | 85% | ${total.branches.pct >= 85 ? ':white_check_mark:' : ':x:'} |
            | Functions | ${total.functions.pct.toFixed(2)}% | 90% | ${total.functions.pct >= 90 ? ':white_check_mark:' : ':x:'} |
            | Statements | ${total.statements.pct.toFixed(2)}% | 90% | ${total.statements.pct >= 90 ? ':white_check_mark:' : ':x:'} |
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });

  coverage-diff:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Get base branch coverage
        run: |
          git checkout ${{ github.base_ref }}
          npm ci
          npm run test:coverage -- --reporter=json-summary
          mv coverage/coverage-summary.json coverage-base.json

      - name: Get PR branch coverage
        run: |
          git checkout ${{ github.head_ref }}
          npm ci
          npm run test:coverage -- --reporter=json-summary
          mv coverage/coverage-summary.json coverage-pr.json

      - name: Compare coverage
        run: |
          BASE_LINES=$(cat coverage-base.json | jq '.total.lines.pct')
          PR_LINES=$(cat coverage-pr.json | jq '.total.lines.pct')
          DIFF=$(echo "$PR_LINES - $BASE_LINES" | bc)

          echo "Base coverage: $BASE_LINES%"
          echo "PR coverage: $PR_LINES%"
          echo "Difference: $DIFF%"

          # Fail if coverage decreased by more than 1%
          if (( $(echo "$DIFF < -1" | bc -l) )); then
            echo "Coverage decreased by more than 1%"
            exit 1
          fi
```

### 5.4 Pre-commit Hook

```bash
#!/bin/bash
# .husky/pre-commit

# Run coverage check on staged files only
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.ts$' | grep '^src/')

if [ -n "$STAGED_FILES" ]; then
  echo "Running coverage check on staged files..."

  # Run tests for affected modules
  npm run test:coverage -- --changed --since=HEAD~1

  COVERAGE_STATUS=$?

  if [ $COVERAGE_STATUS -ne 0 ]; then
    echo "Coverage check failed. Please ensure adequate test coverage."
    exit 1
  fi
fi
```

### 5.5 Package.json Scripts

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest watch",
    "test:coverage": "vitest run --coverage",
    "test:coverage:report": "vitest run --coverage && open coverage/index.html",
    "test:coverage:ci": "vitest run --coverage --reporter=json-summary --reporter=lcov",
    "test:coverage:check": "vitest run --coverage --coverage.thresholds.autoUpdate=false",
    "coverage:view": "open coverage/index.html",
    "coverage:badge": "node scripts/generate-coverage-badge.js"
  }
}
```

---

## 6. Coverage Reporting Tools

### 6.1 Primary Tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| **V8 Coverage** | Native V8 code coverage | Built into Vitest |
| **Codecov** | Coverage hosting & PR comments | GitHub integration |
| **Vitest HTML Reporter** | Local coverage visualization | Development |
| **LCOV** | Universal coverage format | CI/CD pipelines |

### 6.2 Codecov Configuration

```yaml
# codecov.yml
coverage:
  precision: 2
  round: down
  range: "70...100"

  status:
    project:
      default:
        target: 90%
        threshold: 1%
        if_ci_failed: error
        informational: false

      # Module-specific targets
      security-critical:
        paths:
          - "src/keystore/**"
          - "src/policy/**"
          - "src/signing/**"
          - "src/validators/**"
        target: 95%
        threshold: 0.5%

      audit:
        paths:
          - "src/audit/**"
        target: 90%
        threshold: 1%

      integration:
        paths:
          - "src/xrpl/**"
          - "src/mcp/**"
        target: 85%
        threshold: 2%

    patch:
      default:
        target: 90%
        threshold: 5%
        if_ci_failed: error

parsers:
  gcov:
    branch_detection:
      conditional: yes
      loop: yes
      method: no
      macro: no

comment:
  layout: "reach,diff,flags,tree,betaprofiling"
  behavior: default
  require_changes: no
  require_base: yes
  require_head: yes

flags:
  unittests:
    paths:
      - src/
    carryforward: true

  integration:
    paths:
      - tests/integration/
    carryforward: true
```

### 6.3 Local Coverage Viewing

```bash
# Generate and view HTML coverage report
npm run test:coverage:report

# Generate badge for README
npm run coverage:badge
```

### 6.4 Coverage Report Structure

```
coverage/
├── index.html              # Main HTML report
├── lcov.info               # LCOV format for CI
├── coverage-summary.json   # JSON summary
├── coverage-final.json     # Detailed JSON
├── clover.xml              # Clover format
├── cobertura.xml           # Cobertura format
└── src/
    ├── keystore/
    │   ├── index.html
    │   └── local-file.ts.html
    ├── policy/
    │   └── engine.ts.html
    └── ...
```

---

## 7. Coverage Trend Tracking

### 7.1 Historical Tracking

Coverage trends are tracked over time to identify:
- Gradual coverage erosion
- Modules requiring additional testing
- Impact of refactoring on coverage

```typescript
// scripts/track-coverage.ts
interface CoverageSnapshot {
  timestamp: Date;
  commit: string;
  branch: string;
  metrics: {
    overall: CoverageMetrics;
    byModule: Record<string, CoverageMetrics>;
  };
}

interface CoverageMetrics {
  lines: number;
  branches: number;
  functions: number;
  statements: number;
}

async function trackCoverage(): Promise<void> {
  const snapshot = await collectCoverageMetrics();
  await storeCoverageSnapshot(snapshot);
  await generateTrendReport();
}
```

### 7.2 Trend Visualization

```yaml
# Coverage trend dashboard (Grafana/custom)
panels:
  - title: "Overall Coverage Trend"
    type: timeseries
    metrics:
      - lines
      - branches
      - functions
    timeRange: 90d
    threshold: 90

  - title: "Module Coverage Comparison"
    type: bar
    metrics:
      - keystore
      - policy
      - signing
      - validators
      - audit
      - xrpl
      - mcp

  - title: "Coverage Delta per PR"
    type: table
    columns:
      - pr_number
      - coverage_before
      - coverage_after
      - delta
```

### 7.3 Ratcheting Strategy

Coverage thresholds are ratcheted (only increase) to prevent gradual erosion:

```typescript
// vitest.config.ts - Ratcheting configuration
export default defineConfig({
  test: {
    coverage: {
      thresholds: {
        // Enable automatic ratcheting
        autoUpdate: true,

        // Ratchet by 0.5% increments
        '100': false, // Don't require 100%

        // Store thresholds in file
        perFile: true,
      },
    },
  },
});
```

### 7.4 Trend Alerts

```yaml
# Alert configuration
coverage_alerts:
  # Alert if coverage drops more than 2% in a week
  - name: coverage_erosion
    condition: weekly_delta < -2%
    severity: warning
    notify: [devops-team, tech-lead]

  # Alert if security module coverage drops below threshold
  - name: security_coverage_critical
    condition: module_coverage(keystore|policy|signing|validators) < 95%
    severity: critical
    notify: [security-team, tech-lead]

  # Alert if no coverage improvement in 30 days
  - name: coverage_stagnation
    condition: monthly_delta <= 0 AND coverage < 95%
    severity: info
    notify: [qa-team]
```

---

## 8. Remediation Process

### 8.1 Coverage Drop Response

When coverage drops below thresholds, follow this remediation process:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Coverage Drop Detected                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: Identify Uncovered Code                                      │
│ - Review coverage report                                             │
│ - Identify specific functions/branches                               │
│ - Prioritize by security impact                                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 2: Assess Impact                                                │
│ - Is it security-critical code? (Critical)                          │
│ - Is it error handling? (High)                                       │
│ - Is it utility code? (Medium)                                       │
│ - Is it dead code? (Remove)                                          │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 3: Create Tests or Exclude                                      │
│ - Write tests for uncovered paths                                    │
│ - Document legitimate exclusions                                     │
│ - Remove dead code                                                   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Step 4: Verify & Merge                                               │
│ - Run full test suite                                                │
│ - Verify coverage restored                                           │
│ - Review by security team (if security module)                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Remediation Timeline

| Module Type | Max Time to Remediate | Escalation Path |
|-------------|----------------------|-----------------|
| Security-critical | 24 hours | Security Team -> CTO |
| Core infrastructure | 48 hours | Tech Lead -> Engineering Manager |
| Integration modules | 1 week | Tech Lead |
| Utility code | 2 weeks | Code owner |

### 8.3 Coverage Debt Tracking

```typescript
// coverage-debt.json
{
  "debts": [
    {
      "id": "COVERAGE-001",
      "module": "src/xrpl/reconnect.ts",
      "uncovered_lines": [45, 46, 47, 52],
      "reason": "Network edge case requires mock infrastructure",
      "assignee": "qa-engineer",
      "due_date": "2026-02-15",
      "priority": "medium"
    }
  ],
  "total_debt_lines": 4,
  "debt_ratio": 0.1 // 0.1% of codebase
}
```

### 8.4 Remediation Templates

#### Test Addition Template

```typescript
// Template for adding tests to improve coverage
describe('ModuleName - Coverage Remediation', () => {
  // Reference: COVERAGE-XXX
  // Uncovered code: src/module/file.ts lines XX-YY

  describe('Uncovered Branch: [description]', () => {
    it('should handle [scenario]', async () => {
      // Arrange
      const input = /* setup */;

      // Act
      const result = await functionUnderTest(input);

      // Assert
      expect(result).toBe(/* expected */);
    });

    it('should handle [error scenario]', async () => {
      // Arrange
      const badInput = /* error case */;

      // Act & Assert
      await expect(functionUnderTest(badInput))
        .rejects.toThrow('[ExpectedError]');
    });
  });
});
```

#### Exclusion Documentation Template

```typescript
/**
 * Coverage Exclusion: COVERAGE-EXCLUDE-XXX
 *
 * Reason: [Why this code cannot be tested]
 * Alternative validation: [How this code is validated if not through unit tests]
 * Approved by: [Name, Date]
 * Review date: [Date for re-evaluation]
 */
/* istanbul ignore if -- @preserve [Brief reason] */
if (rareCondition) {
  // Code that cannot be easily tested
}
```

---

## Appendix

### A. Coverage Checklist for Pull Requests

```markdown
## Coverage Checklist

- [ ] Overall coverage meets 90% threshold
- [ ] No security-critical module below 95%
- [ ] No new inline exclusions without justification
- [ ] Coverage did not decrease from base branch
- [ ] All new functions have at least one test
- [ ] Error handling paths are tested
- [ ] Edge cases are covered
- [ ] Coverage report reviewed
```

### B. Common Coverage Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Coverage drops on merge | Test conflicts | Rebase and re-run tests |
| Flaky coverage numbers | Non-deterministic tests | Fix test isolation |
| Can't cover error path | Dependency injection missing | Refactor for testability |
| Branch always false | Dead code | Remove unused code |
| Mock prevents coverage | Mock intercepts real code | Use spy instead of mock |

### C. Coverage Commands Quick Reference

```bash
# Run tests with coverage
npm run test:coverage

# View coverage report
npm run coverage:view

# Check specific module coverage
npm run test:coverage -- --coverage.include='src/keystore/**'

# Generate CI report
npm run test:coverage:ci

# Update coverage thresholds (after approval)
npm run test:coverage -- --coverage.thresholds.autoUpdate

# Find uncovered lines
grep -n "0|" coverage/lcov.info | head -20
```

### D. References

- [Vitest Coverage Documentation](https://vitest.dev/guide/coverage.html)
- [V8 Code Coverage](https://v8.dev/blog/javascript-code-coverage)
- [Codecov Documentation](https://docs.codecov.com/)
- [Test Coverage Best Practices](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html)
- [test-patterns-unit.md](./test-patterns-unit.md)
- [test-patterns-integration.md](./test-patterns-integration.md)
- [test-patterns-security.md](./test-patterns-security.md)
- [test-scenarios-e2e.md](./test-scenarios-e2e.md)

---

**Document History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | QA & DevOps Engineer | Initial version |
