use crypto_mac::Mac;
use hmac::Hmac;
use sha2::Sha256;

pub type Result<T> = std::result::Result<T, VerificationError>;

type Sha256Hmac = Hmac<Sha256>;

pub enum VerificationError {
    MissingTimestampHeader,
    VerificationFailed,
}

#[derive(Clone)]
pub struct SlackHTTPVerifier<'a> {
    verifier: SlackVerifier<'a>,
}

impl<'a> SlackHTTPVerifier<'a> {
    pub fn verify<T>(&self, req: http::Request<T>) -> Result<()>
    where
        T: AsRef<str>,
    {
        let ts = req
            .headers()
            .get("X-Slack-Request-Timestamp")
            .ok_or(VerificationError::MissingTimestampHeader)?
            .to_str()
            .unwrap();

        self.verifier.verify(ts, req.body().as_ref())
    }
}

#[derive(Clone)]
struct SlackVerifier<'a> {
    secret: &'a [u8],
}

impl<'a> SlackVerifier<'a> {
    pub fn verify(&self, ts: &str, body: &str) -> Result<()> {
        let basestring = format!("v0:{}:{}", ts, body);
        let mut mac = Sha256Hmac::new_varkey(self.secret.into()).unwrap();

        mac.input(basestring.as_bytes());
        if mac.result().code().as_slice() != self.secret {
            return Err(VerificationError::VerificationFailed)
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
