# valid-pubkeys

Tiny Rust crate to proves a few P-256 facts. Claims:

- `02 || 00…00` (x=0 with even y) is a valid compressed point on P-256, and its y satisfies `y^2 = b (mod p)`.
- The SEC1 identity encoding (`0x00`) corresponds to `d = 0` (point at infinity) and is **not** a usable public key.
- `02 || aa..aa` is **not** a valid P-256 public key (no y exists such that `y^2 = x^3 + ax + b`).

## See for yourself

```bash
cargo test
```
