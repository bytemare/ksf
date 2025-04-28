# Cryptographic Key Stretching Functions
[![ksf](https://github.com/bytemare/ksf/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/ksf/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ksf.svg)](https://pkg.go.dev/github.com/bytemare/ksf)
[![codecov](https://codecov.io/gh/bytemare/ksf/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/ksf)

```
  import "github.com/bytemare/ksf"
```

This package exposes a simple API to seamlessly use a variety of key stretching functions, also used as key derivation
functions. It aims at minimum code adaptation in your code, and easy parameterization.
It completely relies on built-ins, so there's no change in implementations.

Supported Key Stretching Functions (or Key Derivation Functions are):
- Argon2 family
- Scrypt
- PBKDF2

#### What is ksf?

> In cryptography, key stretching techniques are used to make a possibly weak key, typically a password or passphrase,
> more secure against a brute-force attack by increasing the resources (time and possibly space) it takes to test each
> possible key.
> 
> [Wikipedia](https://en.wikipedia.org/wiki/Key_stretching)

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ksf.svg)](https://pkg.go.dev/github.com/bytemare/ksf)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/ksf) and [the project wiki](https://github.com/bytemare/ksf/wiki) .

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/ksf/tags).


## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
