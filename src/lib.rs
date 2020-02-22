use crypto_mac::Mac;
use hmac::Hmac;
use http::header::ToStrError;
use sha2::Sha256;

pub type Result<T> = std::result::Result<T, VerificationError>;

const SLACK_TIMESTAMP_HEADER: &str = "X-Slack-Request-Timestamp";
const SLACK_SIGNATURE_HEADER: &str = "X-Slack-Signature";

type Sha256Hmac = Hmac<Sha256>;

pub enum VerificationError {
    MissingTimestampHeader,
    MissingSignatureHeader,
    SignatureMismatch,
    UnencodableHeader(ToStrError),
}

#[derive(Clone)]
pub struct SlackHTTPVerifier<'a> {
    verifier: SlackVerifier<'a>,
}

impl<'a> SlackHTTPVerifier<'a> {
    pub fn new(secret: &'a [u8]) -> Self {
        SlackHTTPVerifier {
            verifier: SlackVerifier::new(secret),
        }
    }

    pub fn verify<T>(&self, req: http::Request<T>) -> Result<()>
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

#[derive(Clone)]
struct SlackVerifier<'a> {
    secret: &'a [u8],
}

impl<'a> SlackVerifier<'a> {
    pub fn new(secret: &'a [u8]) -> SlackVerifier<'a> {
        SlackVerifier { secret }
    }

    pub fn verify(&self, ts: &str, body: &str, exp_sig: &str) -> Result<()> {
        let basestring = format!("v0:{}:{}", ts, body);
        let mut mac = Sha256Hmac::new_varkey(self.secret.into()).unwrap();

        mac.input(basestring.as_bytes());
        let sig = format!("v0={}", hex::encode(mac.result().code().as_slice()));
        match sig == exp_sig {
            true => Ok(()),
            false => Err(VerificationError::SignatureMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_example() {
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let ts = "1531420618";
        let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let exp_sig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

        let verifier = SlackVerifier::new(secret.as_bytes());
        assert!(verifier.verify(ts, body, exp_sig).is_ok());
    }

    #[test]
    fn site_example_http_req() {
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";

        let req = http::Request::builder()
            .header(SLACK_TIMESTAMP_HEADER, "1531420618")
            .header(SLACK_SIGNATURE_HEADER, "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503")
            .body("token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
            .unwrap();

        let verifier = SlackHTTPVerifier::new(secret.as_bytes());
        assert!(verifier.verify(req).is_ok());
    }
}
