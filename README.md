# tokio-bililive

Simple Bilibili Live Room TCP Listener Based on Tokio Runtime

Really simple implementation. Non zero cost. Lots of copy operation.

## Usage

```bash
cargo add tokio-bililive --git https://github.com/ganlvtech/tokio-bililive.git
```

Or

```toml
[dependencies]
tokio-bililive = { git = "https://github.com/ganlvtech/tokio-bililive.git", version = "0.1.0" }
```

## Examples

See [simple-danmaku](./examples/simple-danmaku/src/main.rs).

Only `DANMU_MSG` struct is provided. If you need to decode other messages, you should define structures by yourself. Try [JSON to Rust Serde](https://transform.tools/json-to-rust-serde).

## LICENSE

[MIT License](https://opensource.org/licenses/MIT)
