# Cryptographic Key Stretching Functions
[![ksf](https://github.com/bytemare/ksf/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/ksf/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ksf.svg)](https://pkg.go.dev/github.com/bytemare/ksf)
[![codecov](https://codecov.io/gh/bytemare/ksf/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/ksf)

```go
import "github.com/bytemare/ksf"
```

`ksf` exposes a simple identifier-based API for password-based key derivation functions. It's a thin Go wrapper around `golang.org/x/crypto`, without reimplementing the underlying primitives.

Supported key stretching functions (KDFs) include:
- Argon2id
- Scrypt
- PBKDF2-SHA512

## What is ksf?

> In cryptography, key stretching techniques are used to make a possibly weak key, typically a password or passphrase,
> more secure against a brute-force attack by increasing the resources (time and possibly space) it takes to test each
> possible key.
>
> [Wikipedia](https://en.wikipedia.org/wiki/Key_stretching)

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ksf.svg)](https://pkg.go.dev/github.com/bytemare/ksf)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/bytemare/ksf) is the canonical API reference.

## Quick Start

```go
h := ksf.Argon2id
salt := h.RandomSalt(0) // 0 falls back to the recommended salt length for the chosen algorithm.

key, err := h.Harden([]byte("password"), salt, 32)
if err != nil {
	panic(err)
}
```

## Custom Parameters

```go
h := ksf.PBKDF2Sha512
parameters := []uint64{10001} // 10001 iterations, which is above the default of 10000

if err := h.VerifyParameters(parameters...); err != nil {
	panic(err)
}

key, err := h.Harden([]byte("password"), []byte("01234567"), 16, parameters...)
if err != nil {
	panic(err)
}
```

## Unknown Identifiers

```go
id := ksf.Identifier(0)

_, err := id.Harden([]byte("password"), []byte("salt"), 16)
if errors.Is(err, ksf.ErrUnknownIdentifier) {
	// handle unsupported or unregistered identifier
}
```

`VerifyParameters` and `Harden` return `ErrUnknownIdentifier` for unsupported identifiers. `UnsafeHarden` and `RandomSalt` panic with the same sentinel error.

## Versioning

[SemVer](https://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/ksf/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
