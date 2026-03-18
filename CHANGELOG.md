# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/ksf/releases).

## [0.5.0] - 2026-03-12

### Added
- Exported `ErrUnknownIdentifier` so callers can use `errors.Is` when an unsupported identifier is requested.
- Added executable examples for default usage, custom parameters, and unsupported identifier handling.
- Added an identifier-centric API for all supported key stretching functions:
  - `Available`
  - `RecommendedSaltLength`
  - `DefaultParameters`
  - `VerifyParameters`
  - `Harden`
  - `UnsafeHarden`
  - `RandomSalt`

### Changed
- Updated to Go 1.26.
- `Harden` now returns errors for invalid parameters and invalid output lengths instead of panicking.
- `VerifyParameters` can be used independently from key derivation to validate custom parameters before use.
- `RandomSalt` now falls back to the algorithm's recommended salt length when called with a non-positive length.
- `String()` now returns only the algorithm name for registered identifiers and `"Unknown KSF"` otherwise.
- Separated the mutating `fmt` workflow from the read-only validation suite exposed via `make -C .github check`.
- Updated the fuzz target to use a temporary Go build cache by default so local runs do not dirty the repository.

### Removed
- Removed the old object-style API, including `Get`, `KSF`, `Parameterize`, and `Salt`.

### Migration
- Replace the old object flow:
  - Before: `k, err := ksf.Get(ksf.Argon2id).Parameterize(params...).Harden(password, salt, length)`
  - After: `k, err := ksf.Argon2id.Harden(password, salt, length, params...)`
- Replace `Salt()` with `RandomSalt(length)` on the identifier you want to use.
- Audit any previous panic-based invalid-input handling. `Harden` and `VerifyParameters` now report failures as errors, while `UnsafeHarden` keeps panic semantics.

[0.5.0]: https://github.com/bytemare/ksf/releases/tag/v0.5.0
