# Contributing to XRPL Wallet MCP

Thank you for your interest in contributing to the XRPL Wallet MCP Server. This project provides secure, policy-controlled wallet infrastructure for AI agents on the XRP Ledger, and we welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Commit Conventions](#commit-conventions)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Documentation](#documentation)
- [Testing Requirements](#testing-requirements)
- [License](#license)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. By participating, you agree to uphold a welcoming, inclusive, and harassment-free environment.

**Core principles:**

- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Accept responsibility for mistakes and learn from them

## Getting Started

Before contributing, please:

1. Read this entire document
2. Review existing [issues](https://github.com/9RESE/xrpl-agent-wallet-mcp/issues) and [pull requests](https://github.com/9RESE/xrpl-agent-wallet-mcp/pulls)
3. Check the [README](README.md) for project overview
4. Review [SECURITY.md](SECURITY.md) for security-related contributions

## Development Setup

### Prerequisites

- **Node.js**: Version 22.0.0 or higher (required)
- **npm**: Comes with Node.js (we use npm, not yarn or pnpm)
- **Git**: For version control
- **Editor**: VS Code recommended (with ESLint and Prettier extensions)

Verify your setup:

```bash
node --version  # Should be >= 22.0.0
npm --version   # Should be >= 10.0.0
```

### Clone and Install

1. **Fork the repository** on GitHub

2. **Clone your fork:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/xrpl-agent-wallet-mcp.git
   cd xrpl-agent-wallet-mcp
   ```

3. **Add the upstream remote:**

   ```bash
   git remote add upstream https://github.com/9RESE/xrpl-agent-wallet-mcp.git
   ```

4. **Install dependencies:**

   ```bash
   npm install
   ```

5. **Verify the setup:**

   ```bash
   npm run build      # Should compile without errors
   npm run test:run   # Should pass all tests
   npm run lint       # Should pass linting
   ```

### Development Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development mode with hot reload |
| `npm run build` | Build for production |
| `npm run test` | Run tests in watch mode |
| `npm run test:run` | Run tests once |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run test:ui` | Open Vitest UI |
| `npm run lint` | Check for linting errors |
| `npm run lint:fix` | Auto-fix linting errors |
| `npm run format` | Format code with Prettier |
| `npm run format:check` | Check code formatting |
| `npm run typecheck` | Run TypeScript type checking |

## Code Style

We use ESLint and Prettier to maintain consistent code style.

### ESLint

- Configuration: ESLint 9.x flat config with TypeScript support
- Run linting: `npm run lint`
- Auto-fix: `npm run lint:fix`

### Prettier

- Configuration: Prettier 3.x with default settings
- Format code: `npm run format`
- Check formatting: `npm run format:check`

### TypeScript Guidelines

- Use strict mode (enabled in `tsconfig.json`)
- Prefer explicit return types on exported functions
- Use `const` assertions where appropriate
- Avoid `any` type; use `unknown` when type is truly unknown
- Document complex types with JSDoc comments

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Files | kebab-case | `wallet-manager.ts` |
| Classes | PascalCase | `WalletManager` |
| Interfaces | PascalCase with `I` prefix (optional) | `WalletConfig` |
| Functions | camelCase | `createWallet()` |
| Constants | SCREAMING_SNAKE_CASE | `MAX_RETRY_COUNT` |
| Variables | camelCase | `walletAddress` |
| Types | PascalCase | `TransactionResult` |

### Editor Configuration

For VS Code, add these settings to your workspace:

```json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": "explicit"
  },
  "typescript.preferences.importModuleSpecifier": "relative"
}
```

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/) for clear, semantic commit history.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only changes |
| `style` | Formatting, semicolons, etc. (no code change) |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or correcting tests |
| `build` | Changes to build system or dependencies |
| `ci` | Changes to CI configuration |
| `chore` | Other changes that don't modify src or test files |
| `revert` | Reverts a previous commit |

### Scopes

| Scope | Description |
|-------|-------------|
| `wallet` | Wallet management functionality |
| `policy` | Policy engine and validation |
| `crypto` | Cryptographic operations |
| `mcp` | MCP protocol integration |
| `audit` | Audit logging |
| `api` | Public API changes |
| `deps` | Dependency updates |

### Examples

```bash
# Feature
feat(wallet): add multi-signature wallet support

# Bug fix
fix(policy): correct rate limit calculation for burst mode

# Breaking change
feat(api)!: redesign transaction signing interface

BREAKING CHANGE: The signTransaction method now requires a TransactionRequest object instead of raw parameters.

# Documentation
docs: update API reference for wallet creation

# Dependencies
build(deps): upgrade xrpl to v4.2.0
```

### Commit Message Guidelines

- Use imperative mood: "add" not "added" or "adds"
- Keep the subject line under 72 characters
- Don't end the subject line with a period
- Separate subject from body with a blank line
- Use the body to explain what and why, not how

## Pull Request Process

### Before Creating a PR

1. **Sync with upstream:**

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create a feature branch:**

   ```bash
   git checkout -b feat/your-feature-name
   ```

3. **Make your changes** following our code style

4. **Run all checks:**

   ```bash
   npm run typecheck
   npm run lint
   npm run format:check
   npm run test:coverage
   ```

5. **Ensure tests pass** with adequate coverage

### Creating the PR

1. **Push your branch:**

   ```bash
   git push origin feat/your-feature-name
   ```

2. **Open a Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Clear description of changes
   - Related issue numbers (e.g., "Closes #123")
   - Screenshots for UI changes
   - Testing instructions
   - Breaking changes (if any)

### PR Requirements

All PRs must meet these requirements before merging:

- [ ] All CI checks pass
- [ ] Code coverage >= 90% for new code
- [ ] No decrease in overall coverage
- [ ] At least one approving review
- [ ] All review comments addressed
- [ ] Commits follow conventional commit format
- [ ] Documentation updated (if applicable)
- [ ] No merge conflicts with main

### Review Process

1. **Automated Review**: CI runs tests, linting, and type checks
2. **Code Review**: Maintainers review for:
   - Code quality and style
   - Security implications
   - Performance considerations
   - Test coverage
   - Documentation completeness
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, a maintainer will merge

### After Merge

- Delete your feature branch
- Update your local main:

  ```bash
  git checkout main
  git pull upstream main
  git push origin main
  ```

## Issue Reporting

### Bug Reports

When reporting bugs, include:

1. **Environment**: Node.js version, OS, npm version
2. **Description**: Clear description of the bug
3. **Steps to Reproduce**: Minimal steps to reproduce
4. **Expected Behavior**: What should happen
5. **Actual Behavior**: What actually happens
6. **Logs/Screenshots**: Any relevant output
7. **Possible Solution**: If you have one

### Feature Requests

For new features, provide:

1. **Problem Statement**: What problem does this solve?
2. **Proposed Solution**: How would it work?
3. **Alternatives Considered**: Other approaches you considered
4. **Additional Context**: Use cases, examples, etc.

### Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `documentation` | Documentation improvements |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `security` | Security-related issues |
| `breaking` | Breaking change |

## Security Vulnerabilities

**Do NOT report security vulnerabilities through public GitHub issues.**

Please read [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

For security issues:

1. **Preferred**: Use GitHub Security Advisories
2. **Alternative**: Email contact@9rese.com

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Documentation

### Types of Documentation

| Location | Purpose |
|----------|---------|
| `README.md` | Project overview and quick start |
| `docs/` | Detailed documentation |
| `docs/api/` | API reference |
| `docs/architecture/` | Architecture documentation |
| Code comments | Inline explanations |

### Documentation Guidelines

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting
- Add diagrams for complex concepts (using Mermaid)

### Contributing Documentation

1. Documentation changes follow the same PR process
2. Preview changes locally before submitting
3. Ensure all links work
4. Run spell check

## Testing Requirements

### Coverage Requirements

| Code Type | Minimum Coverage |
|-----------|------------------|
| New code | 90% |
| Legacy code | 80% |
| Critical paths (crypto, security) | 95% |

### Test Structure

```
tests/
├── unit/           # Unit tests for individual functions
├── integration/    # Integration tests for modules
└── e2e/           # End-to-end tests (if applicable)
```

### Writing Tests

- Use descriptive test names: `should return error when wallet not found`
- Follow AAA pattern: Arrange, Act, Assert
- Test edge cases and error conditions
- Mock external dependencies
- Keep tests independent and isolated

### Running Tests

```bash
# Run all tests
npm run test:run

# Run with coverage
npm run test:coverage

# Run specific test file
npm run test -- tests/unit/wallet.test.ts

# Run tests matching pattern
npm run test -- -t "wallet creation"
```

### Test Coverage Report

After running `npm run test:coverage`, check:

- `coverage/` directory for detailed reports
- `coverage/lcov-report/index.html` for HTML report

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

### Contribution License Agreement

By submitting a pull request, you represent that:

1. You have the right to license your contribution to the project
2. Your contributions are your original work
3. You grant the project maintainers a perpetual, worldwide, non-exclusive, royalty-free license to use your contribution

---

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/9RESE/xrpl-agent-wallet-mcp/discussions)
- **Bug reports**: Open an [Issue](https://github.com/9RESE/xrpl-agent-wallet-mcp/issues)
- **Security issues**: See [SECURITY.md](SECURITY.md)

Thank you for contributing to XRPL Wallet MCP.
