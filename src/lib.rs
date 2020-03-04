//! slack_http_verifier verifies request signatures from Slacks HTTP Events API,
//! as described
//! [here](https://api.slack.com/docs/verifying-requests-from-slack#sdk_support).
//!
//! ## Usage
//!
//! If you're using the `http` crate, requests can be verified directly
//! ```edition2018
//! use slack_http_verifier::SlackHTTPVerifier;
//!
//! // Sample from Slack's documentation page - do not use this in your own code
//! let my_secret_key: &str = "8f742231b10e8888abcd99yyyzzz85a5";
//! let slack_sample_timestamp: &str = "1531420618";
//! let slack_sample_body: &str =
//!     "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
//! let slack_sample_sig: &str =
//!     "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
//!
//! let http_verifier = SlackHTTPVerifier::new(my_secret_key).unwrap();
//!
//! // ...
//! // Receive requests
//!
//! let req = http::Request::builder()
//!     .header("X-Slack-Request-Timestamp", slack_sample_timestamp)
//!     .header("X-Slack-Signature", slack_sample_sig)
//!     .body(slack_sample_body)
//!     .unwrap();
//!
//! http_verifier.verify(&req).unwrap();
//! ```
//!
//! They can also be verified using the raw body directly, encoded as a string.
//! ```edition2018
//! # use slack_http_verifier::SlackVerifier;
//!
//! // Sample from Slack's documentation page - do not use this in your own code
//! let my_secret_key: &str = "8f742231b10e8888abcd99yyyzzz85a5";
//!
//! let verifier = SlackVerifier::new(my_secret_key).unwrap();
//!
//! // ...
//! // Receive requests, extract from your framework
//!
//! let slack_sample_timestamp: &str = "1531420618";
//! let slack_sample_body: &str =
//!     "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
//! let slack_sample_sig: &str =
//!     "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
//!
//! verifier
//!     .verify(slack_sample_timestamp, slack_sample_body, slack_sample_sig)
//!     .unwrap();
//! ```

use crypto_mac::Mac;
use hmac::Hmac;
use sha2::Sha256;

const SLACK_TIMESTAMP_HEADER: &str = "X-Slack-Request-Timestamp";
const SLACK_SIGNATURE_HEADER: &str = "X-Slack-Signature";

type Sha256Hmac = Hmac<Sha256>;

mod error {
    use http::header::ToStrError;

    #[derive(Debug)]
    pub struct InvalidKeyLengthError;

    #[derive(Debug)]
    pub enum VerificationError {
        MissingTimestampHeader,
        MissingSignatureHeader,
        SignatureMismatch,
        UnencodableHeader(ToStrError),
    }
}

use error::*;

/// Verifies Slack [http request][http::Request]s are signed by the given secret.
/// A convenience wrapper around [`SlackVerifier`][SlackVerifier].
#[derive(Clone, Debug)]
pub struct SlackHTTPVerifier {
    verifier: SlackVerifier,
}

impl SlackHTTPVerifier {
    /// Returns a new SlackHTTPVerifier.
    ///
    /// ```edition2018
    /// # use slack_http_verifier::SlackHTTPVerifier;
    ///
    /// let verifier = SlackHTTPVerifier::new("8f742231b10e8888abcd99yyyzzz85a5").unwrap();
    /// ```
    pub fn new<S: AsRef<[u8]>>(secret: S) -> Result<Self, InvalidKeyLengthError> {
        let verifier = SlackVerifier::new(secret)?;
        Ok(SlackHTTPVerifier { verifier })
    }

    /// Verifies the given request.
    ///
    /// ```edition2018
    /// # use slack_http_verifier::SlackHTTPVerifier;
    /// # let verifier = SlackHTTPVerifier::new("8f742231b10e8888abcd99yyyzzz85a5").unwrap();
    /// # let req = http::Request::builder()
    /// #     .header("X-Slack-Request-Timestamp", "1531420618")
    /// #     .header("X-Slack-Signature", "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503")
    /// #     .body("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
    /// #     .unwrap();
    ///
    /// assert!(verifier.verify(&req).is_ok())
    /// ```
    pub fn verify<T>(&self, req: &http::Request<T>) -> Result<(), VerificationError>
    where
        T: AsRef<str>,
    {
        let ts = req
            .headers()
            .get(SLACK_TIMESTAMP_HEADER)
            .ok_or(VerificationError::MissingTimestampHeader)?
            .to_str()
            .map_err(VerificationError::UnencodableHeader)?;

        let exp_sig = req
            .headers()
            .get(SLACK_SIGNATURE_HEADER)
            .ok_or(VerificationError::MissingSignatureHeader)?
            .to_str()
            .map_err(VerificationError::UnencodableHeader)?;

        self.verifier.verify(ts, req.body().as_ref(), exp_sig)
    }
}

unsafe impl Send for SlackHTTPVerifier {}

unsafe impl Sync for SlackHTTPVerifier {}

/// Verifies raw request bodies are signed by Slack's secret.
/// An alternative if it is inconvenient/impossible to use
/// SlackHTTPVerifier
#[derive(Clone, Debug)]
pub struct SlackVerifier {
    mac: Sha256Hmac,
}

impl SlackVerifier {
    /// Returns a new SlackVerifier.
    ///
    /// ```edition2018
    /// # use slack_http_verifier::SlackVerifier;
    /// let verifier = SlackVerifier::new("8f742231b10e8888abcd99yyyzzz85a5").unwrap();
    /// ```
    pub fn new<S: AsRef<[u8]>>(secret: S) -> Result<SlackVerifier, InvalidKeyLengthError> {
        match Sha256Hmac::new_varkey(secret.as_ref()) {
            Ok(mac) => Ok(SlackVerifier { mac }),
            Err(_) => Err(InvalidKeyLengthError),
        }
    }

    /// Verifies the given request.
    ///
    /// ```edition2018
    /// # use slack_http_verifier::SlackVerifier;
    /// # let ts_header = "1531420618";
    /// # let req_body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    /// # let sig_header = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    /// # let verifier = SlackVerifier::new("8f742231b10e8888abcd99yyyzzz85a5").unwrap();
    ///
    /// assert!(verifier.verify(ts_header, req_body, sig_header).is_ok());
    /// ```
    pub fn verify(&self, ts: &str, body: &str, exp_sig: &str) -> Result<(), VerificationError> {
        let basestring = format!("v0:{}:{}", ts, body);
        let mut mac = self.mac.clone();

        mac.input(basestring.as_bytes());
        let sig = format!("v0={}", hex::encode(mac.result().code().as_slice()));
        match sig == exp_sig {
            true => Ok(()),
            false => Err(VerificationError::SignatureMismatch),
        }
    }
}

unsafe impl Send for SlackVerifier {}

unsafe impl Sync for SlackVerifier {}

#[cfg(test)]
mod tests {
    use super::*;

    const SLACK_SAMPLE_KEY: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const SLACK_SAMPLE_TIMESTAMP: &str = "1531420618";
    const SLACK_SAMPLE_BODY: &str =
        "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SLACK_SAMPLE_SIG: &str =
        "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

    #[test]
    fn site_example() {
        let verifier = SlackVerifier::new(SLACK_SAMPLE_KEY).unwrap();
        assert!(verifier
            .verify(SLACK_SAMPLE_TIMESTAMP, SLACK_SAMPLE_BODY, SLACK_SAMPLE_SIG)
            .is_ok());
    }

    #[test]
    fn site_example_http_req() {
        let verifier = SlackHTTPVerifier::new(SLACK_SAMPLE_KEY).unwrap();

        let req = http::Request::builder()
            .header(SLACK_TIMESTAMP_HEADER, SLACK_SAMPLE_TIMESTAMP)
            .header(SLACK_SIGNATURE_HEADER, SLACK_SAMPLE_SIG)
            .body(SLACK_SAMPLE_BODY)
            .unwrap();

        assert!(verifier.verify(&req).is_ok());
    }
}
