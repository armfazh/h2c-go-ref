# RFC9380 - Hashing to Elliptic Curves

![Go](https://github.com/armfazh/h2c-go-ref/workflows/Go/badge.svg)

---

**IETF Data Tracker**: [draft-irtf-cfrg-hash-to-curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve)

**Internet RFC-9380**: [git repository](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve)

This document specifies a number of algorithms that may be used to encode or hash an arbitrary string to a point on an elliptic curve.

### Reference Implementation

The purpose of this implementation is for generating test vectors and enabling cross compatibility with other implementations.

This implementation is for reference only. It **MUST NOT** be used in production systems.

**Development branch**: [master](https://github.com/armfazh/h2c-go-ref/tree/master)

#### Draft versions implemented
 **Latest**: [v14]

 Previous: [v12], [v10], [v08], [v07], [v06], [v05].

 [v14]: https://github.com/armfazh/h2c-go-ref/tree/v14.0.0
 [v12]: https://github.com/armfazh/h2c-go-ref/tree/v12.0.0
 [v10]: https://github.com/armfazh/h2c-go-ref/tree/v10.0.1
 [v08]: https://github.com/armfazh/h2c-go-ref/tree/v8.0.0
 [v07]: https://github.com/armfazh/h2c-go-ref/tree/v7.0.0
 [v06]: https://github.com/armfazh/h2c-go-ref/tree/v6.0.0
 [v05]: https://github.com/armfazh/h2c-go-ref/tree/v5.0.0

#### Compatible Implementations
 -   [Sage](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc)
 -   [rust](https://github.com/armfazh/h2c-rust-ref)


### Internals

![hash to curve](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/drawings/diag.png)

### Contact

Feel free to open a github issue for anything related to the implementation, otherwise [e-mail](mailto:draft-irtf-cfrg-hash-to-curve@ietf.org) authors of the draft.
