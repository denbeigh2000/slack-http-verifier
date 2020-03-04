# slack-http-verifier

<a href="https://docs.rs/slack-http-verifier" alt="View documentation on docs.rs">
    <img src="https://docs.rs/slack-http-verifier/badge.svg" /></a>
<a href="https://crates.io/crates/slack-http-verifier" alt="View on crates.io">
    <img src="https://img.shields.io/crates/v/slack-http-verifier.svg" /></a>
<a href="https://travis-ci.com/denbeigh2000/slack-http-verifier" alt="View builds on Travis CI">
    <img src="https://travis-ci.com/denbeigh2000/slack-http-verifier.svg?branch=master" /></a>


This crate implements verification of Slack's request tokens, as described
[here](https://api.slack.com/docs/verifying-requests-from-slack#sdk_support).

There is out-of-the-box support for reqwest::blocking::Request, and
http::Request, but you can create a newtype implementing `HTTPRequest` to suit
your own needs.

Use the HTTP Request API:
```rust
use slack_http_verifier::SlackHTTPVerifier;

let verifier = SlackHTTPVerifier::new("abcd1234...").unwrap();

// ... Receive a request somehow ...

assert!(verifier.verify(&req).is_ok());
```

Or use the raw API:
```rust
use slack_http_verifier::SlackVerifier;

let verifier = SlackVerifier::new("abcd1234...").unwrap();

// ... Receive a request somehow ...
let ts = req.get("X-Slack-Request-Timestamp");
let sig = req.get("X-Slack-Signature");
let body = req.body().as_str();

assert!(verifier.verify(&ts, &body, &sig).is_ok());
```
