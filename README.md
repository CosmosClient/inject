# cosmos-inject

A simple process injection library Cosmos uses inject dynamic libraries into running processes. Just works ✨️

```rust
cosmos_inject::inject(pid, "/path/to/lib.dylib".into())?;
```

Supports Windows and macOS (with SIP disabled). Linux support planned.
