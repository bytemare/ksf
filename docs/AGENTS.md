# AGENTS.md

## Project Context

This is a Go cryptography library described in README.md.
Security is a first-class citizen.

## Documentation Standards

Most open source related documentation files are templated to ensure consistency across Bytemare projects.

The documents that need specific attention are:
- docs/ architecture_and_guidelines.md
- docs/security_model.md

Both must be completed with the highest quality and state-of-the-art content.

### Quality Bar
- No redundancy: each fact lives in one place, others reference it
- Cross-link documents; no orphan pages; relative links with .md extension
- Panic conditions documented in architecture doc
- Security reporting in SECURITY.md only; other docs reference it
- Ensure clarity, accuracy, and consistency across all documents.

### Anti-patterns to Avoid
- Duplicating make/validation commands across docs
- Mixing conduct and security reporting channels
- Broken internal links (check extensions and case)
- Missing CHANGELOG.md entries for user-facing changes

## Coding Standards

- Documentation
  - Coding decisions are documented in the code comments where non-obvious
  - Example code is provided for all public APIs and common scenarios
  - Documentation of security considerations for public APIs

- Coding practices
  - Follow Effective Go and Go Code Review Comments
  - Follow Go Cryptography Principles (https://go.googlesource.com/proposal/+/master/design/cryptography-principles.md)
  - Clean architecture principles
  - Defensive programming
  - Clear error handling and logging practices
  - Adherence to secure coding guidelines and best practices
  - Use of static analysis tools to detect potential security issues
  - Interface design: the interface/API is designed to be easy to use securely, and difficult to misuse in an insecure way.
  - Use secure defaults: any configurable options should default to the most secure settings.
  - rigorous input validation
  - Output is properly sanitized and encoded to prevent injection attacks
  - SPDX license headers in source files

- Security
  - No vulnerabilities, no backdoors, no malicious code
  - No secret-dependent branching
  - No secret-dependent memory access
  - Use of constant-time comparison functions for sensitive data
  - Use of established cryptographic libraries and algorithms
  - Avoidance of deprecated or weak cryptographic primitives

- Commits
  - Conventional Commits for commit messages
  - DCO sign-off required on all commits
  - SSH or GPG-signed commits

- High-assurance software engineering
  - we're aiming for CA-2 (minimum) or higher 

- Testing
  - Use fuzzing where applicable
  - Property-based testing where applicable
  - Complete functional tests, including edge cases
  - Security tests, including tests for known vulnerabilities
  - Table driven tests for functions with multiple edge cases
  - Aim for high test coverage, possibly 100%, and accept unreachable code that is there for defensive programming
