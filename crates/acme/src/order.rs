//! One order for one certificate, as a state machine (RFC 8555, section 7).
//!
//! ```text
//! Directory -> Nonce -> Account -> NewOrder -> Authorization -> Present
//!                                                   |               |
//!                                                   | (valid)       v
//!      Done <- Download <- PollOrder <- Finalize <--+--- PollAuthorization <- Respond
//! ```
//!
//! A phase moves forward only. Every request takes one unit of a budget, so an order
//! ends. `docs/sid/assets/automatic-https.lean` proves both for a model of this machine.

use sibuna_json::{Object, Value};

use crate::error::printable;
use crate::{Error, KeyPair, csr, jws};

/// The requests one order may send.
pub const BUDGET: u32 = 48;
/// The largest response body the machine reads.
pub const MAX_BODY: usize = 128 * 1024;
/// The longest URL the authority may name.
const MAX_URL: usize = 2048;
/// The longest nonce and the longest token.
const MAX_TOKEN: usize = 512;
/// The most challenges read from one authorization.
const MAX_CHALLENGES: usize = 16;
/// The longest wait the authority may ask for between two polls, in seconds.
const MAX_WAIT: u64 = 30;

/// Bounds of the JSON documents of the authority.
pub(crate) const LIMITS: sibuna_json::Limits = sibuna_json::Limits {
    max_input_bytes: MAX_BODY,
    max_values: 4096,
    max_string_bytes: 8192,
    max_depth: 16,
};

/// The method of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Fetch the directory.
    Get,
    /// Fetch a nonce.
    Head,
    /// Everything else. The body is a JWS with the type `application/jose+json`.
    Post,
}

/// A request for the caller to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The absolute URL.
    pub url: String,
    /// The body of a POST, empty otherwise.
    pub body: String,
}

/// The parts of a response that the machine reads. The caller bounds the body by
/// [`MAX_BODY`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The header `Location`.
    pub location: Option<String>,
    /// The header `Replay-Nonce`.
    pub nonce: Option<String>,
    /// The header `Retry-After`, when it is a number of seconds.
    pub retry_after: Option<u64>,
    /// The body.
    pub body: Vec<u8>,
}

/// A challenge type that the daemon can answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeKind {
    /// A file under `/.well-known/acme-challenge/` on port 80.
    Http01,
    /// A certificate on port 443 for the protocol `acme-tls/1`.
    TlsAlpn01,
    /// A TXT record `_acme-challenge.NAME`. The only type that proves a wildcard.
    Dns01,
}

impl ChallengeKind {
    /// The name of the type in the protocol.
    pub fn word(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Dns01 => "dns-01",
        }
    }

    /// The other type that a listener of ours can answer. DNS-01 has no other.
    pub fn other(self) -> Self {
        match self {
            Self::Http01 => Self::TlsAlpn01,
            Self::TlsAlpn01 => Self::Http01,
            Self::Dns01 => Self::Dns01,
        }
    }
}

/// A challenge to answer before the order goes on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The type the machine chose.
    pub kind: ChallengeKind,
    /// The name under validation.
    pub name: String,
    /// The token of the authority: base64url characters only.
    pub token: String,
    /// The token, a dot and the thumbprint of the account key.
    pub key_authorization: String,
}

impl Challenge {
    /// The owner of the TXT record of DNS-01, without a final dot: `_acme-challenge.`
    /// and the name without its `*.` (RFC 8555, section 8.4).
    pub fn dns_owner(&self) -> String {
        format!("_acme-challenge.{}", self.name.strip_prefix("*.").unwrap_or(&self.name))
    }

    /// The text of the TXT record of DNS-01: the SHA-256 digest of the key
    /// authorization in base64url.
    pub fn dns_value(&self) -> String {
        let digest = sibuna_crypto::sha256::Sha256::digest(self.key_authorization.as_bytes());
        jws::base64url(&digest)
    }
}

/// An issued certificate.
#[derive(Debug)]
pub struct Issued {
    /// The chain as PEM, leaf first, as the authority sent it.
    pub chain_pem: String,
    /// The private key of the leaf.
    pub key: KeyPair,
}

/// What the caller does next.
#[derive(Debug)]
pub enum Action {
    /// Send this request and pass the response to [`Order::advance`].
    Send(Request),
    /// Publish the answer to this challenge, then call [`Order::presented`].
    Present(Challenge),
    /// Wait this many seconds, then call [`Order::resume`].
    Wait(u64),
    /// The order ended with a certificate.
    Done(Box<Issued>),
    /// The order ended without one.
    Failed(Error),
}

/// The account at one authority: its key and, once registered, its URL.
#[derive(Debug)]
pub struct Account {
    key: KeyPair,
    url: Option<String>,
}

impl Account {
    /// An account for `key`. The first order registers it, or finds it at the authority.
    pub fn new(key: KeyPair) -> Self {
        Self { key, url: None }
    }

    /// The account key.
    pub fn key(&self) -> &KeyPair {
        &self.key
    }

    /// The thumbprint of the account key, the second half of every key authorization.
    pub fn thumbprint(&self) -> String {
        jws::thumbprint(&self.key)
    }
}

/// What to order. Fill the fields and call [`Order::begin`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderOptions {
    /// The URL of the ACME directory.
    pub directory: String,
    /// The DNS name to order a certificate for.
    pub name: String,
    /// The contact address of a new account, without `mailto:`.
    pub email: Option<String>,
    /// The challenge type to answer.
    pub challenge: ChallengeKind,
    /// Answer the other type when the authority does not offer `challenge`.
    pub any_challenge: bool,
    /// The external account binding of a new account, for an authority that wants one.
    pub binding: Option<jws::Binding>,
    /// The identifier of the certificate that this order replaces (RFC 9773, section
    /// 5). It is sent when the directory offers renewal information.
    pub replaces: Option<String>,
    /// The curve of the key of the certificate.
    pub curve: crate::Curve,
}

impl Default for OrderOptions {
    /// No name, the production directory of Let's Encrypt, HTTP-01 or else TLS-ALPN-01.
    fn default() -> Self {
        Self {
            directory: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
            name: String::new(),
            email: None,
            challenge: ChallengeKind::Http01,
            any_challenge: true,
            binding: None,
            replaces: None,
            curve: crate::Curve::P256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Directory,
    Nonce,
    Account,
    NewOrder,
    Authorization,
    Present,
    Respond,
    PollAuthorization,
    Finalize,
    PollOrder,
    Download,
    Done,
    Failed,
}

/// The URLs of the directory.
#[derive(Default)]
struct Endpoints {
    new_nonce: String,
    new_account: String,
    new_order: String,
    /// Whether the directory offers renewal information.
    renewal_info: bool,
}

/// One order in progress. It borrows the account for its whole life.
pub struct Order<'a> {
    account: &'a mut Account,
    options: OrderOptions,
    phase: Phase,
    budget: u32,
    polls: u32,
    nonce: Option<String>,
    endpoints: Endpoints,
    order_url: String,
    authorization_url: String,
    finalize_url: String,
    certificate_url: String,
    challenge_url: String,
    challenge: Option<Challenge>,
    key: Option<KeyPair>,
}

fn unexpected(what: &str) -> Error {
    Error::unexpected(format!("The authority sent an answer we cannot use: {what}."))
}

/// The members of a JSON object in a response body.
fn object(body: &[u8]) -> Result<Value<'_>, Error> {
    let value = sibuna_json::parse_with_limits(body, &LIMITS)
        .map_err(|error| unexpected(&format!("its body is not the expected JSON ({error})")))?;
    if value.as_object().is_none() {
        return Err(unexpected("its body is not a JSON object"));
    }
    Ok(value)
}

fn member<'v>(object: &'v Object<'_>, key: &str) -> Result<&'v str, Error> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| unexpected(&format!("the member `{key}` is missing")))
}

/// Whether `text` is a token of base64url characters, as RFC 8555 requires of a nonce
/// and of a challenge token.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_TOKEN
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A problem document (RFC 7807): the last word of its type, such as `badNonce`, and
/// the failure it describes.
fn problem(response: &Response) -> (String, Error) {
    let parsed = object(&response.body).ok();
    let members = parsed.as_ref().and_then(Value::as_object);
    let text = |key: &str| {
        let value = members.and_then(|m| m.get(key)).and_then(Value::as_str).unwrap_or("-");
        printable(value, 300)
    };
    let kind = text("type");
    let word = kind.rsplit(':').next().unwrap_or_default().to_owned();
    let message = format!(
        "The authority answered {} with the problem `{kind}`: {}",
        response.status,
        text("detail")
    );
    if response.status == 429 || word == "rateLimited" {
        return (word, Error::rate_limited(message, response.retry_after));
    }
    (word, Error::refused(message))
}

/// The reason in the `error` member of an order, an authorization or a challenge.
fn reason(members: &Object<'_>) -> String {
    let detail = members
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("detail"))
        .and_then(Value::as_str);
    printable(detail.unwrap_or("no reason given"), 300)
}

impl<'a> Order<'a> {
    /// Starts an order and returns its first action, the request for the directory.
    pub fn begin(account: &'a mut Account, options: OrderOptions) -> (Self, Action) {
        let mut order = Self {
            account,
            options,
            phase: Phase::Directory,
            budget: BUDGET,
            polls: 0,
            nonce: None,
            endpoints: Endpoints::default(),
            order_url: String::new(),
            authorization_url: String::new(),
            finalize_url: String::new(),
            certificate_url: String::new(),
            challenge_url: String::new(),
            challenge: None,
            key: None,
        };
        let action = order.send();
        (order, action)
    }

    /// Whether the order ended, with or without a certificate.
    pub fn is_over(&self) -> bool {
        self.phase >= Phase::Done
    }

    fn fail(&mut self, error: Error) -> Action {
        self.phase = Phase::Failed;
        Action::Failed(error)
    }

    /// Checks a URL of the authority: bounded, without white space, and with the scheme
    /// of the directory. A directory with `https` never sends us to `http`.
    fn checked_url(&self, url: &str) -> Result<String, Error> {
        let secure = self.options.directory.starts_with("https://");
        let scheme_ok = url.starts_with("https://") || (!secure && url.starts_with("http://"));
        let plain = url.bytes().all(|byte| byte.is_ascii_graphic());
        if !scheme_ok || !plain || url.len() > MAX_URL {
            return Err(unexpected("a URL is malformed or leaves the scheme of the directory"));
        }
        Ok(url.to_owned())
    }

    /// The request of the current phase. Takes one unit of budget.
    fn send(&mut self) -> Action {
        if self.budget == 0 {
            return self.fail(Error::unexpected(format!(
                "The order for `{}` needed more than {BUDGET} requests.",
                self.options.name
            )));
        }
        self.budget -= 1;
        match self.request() {
            Ok(request) => Action::Send(request),
            Err(error) => self.fail(error),
        }
    }

    fn request(&mut self) -> Result<Request, Error> {
        let plain =
            |method, url: &str| Request { method, url: url.to_owned(), body: String::new() };
        let (url, payload) = match self.phase {
            Phase::Directory => return Ok(plain(Method::Get, &self.options.directory)),
            Phase::Nonce => return Ok(plain(Method::Head, &self.endpoints.new_nonce)),
            Phase::Account => (self.endpoints.new_account.clone(), self.registration()),
            Phase::NewOrder => (self.endpoints.new_order.clone(), self.new_order()),
            Phase::Authorization | Phase::PollAuthorization => {
                (self.authorization_url.clone(), String::new())
            }
            Phase::Respond => (self.challenge_url.clone(), "{}".to_owned()),
            Phase::Finalize => (self.finalize_url.clone(), self.certificate_request()?),
            Phase::PollOrder => (self.order_url.clone(), String::new()),
            Phase::Download => (self.certificate_url.clone(), String::new()),
            Phase::Present | Phase::Done | Phase::Failed => {
                return Err(unexpected("no request belongs to this phase"));
            }
        };
        let nonce = self.nonce.take().ok_or_else(|| unexpected("it sent no nonce"))?;
        let account = self.account.url.as_deref().filter(|_| self.phase != Phase::Account);
        let body = jws::sign(&self.account.key, account, &nonce, &url, &payload)?;
        Ok(Request { method: Method::Post, url, body })
    }

    /// Draws the key of the certificate and writes the payload that finalizes the order.
    fn certificate_request(&mut self) -> Result<String, Error> {
        let key = KeyPair::generate_on(self.options.curve)?;
        let request = csr::write(&key, &[self.options.name.as_str()])?;
        self.key = Some(key);
        Ok(format!(r#"{{"csr":"{}"}}"#, jws::base64url(&request)))
    }

    /// The certificate that the order replaces, when the directory takes the member.
    fn replaced(&self) -> Option<&str> {
        self.options.replaces.as_deref().filter(|_| self.endpoints.renewal_info)
    }

    /// The payload that places the order.
    fn new_order(&self) -> String {
        let mut payload = String::from(r#"{"identifiers":[{"type":"dns","value":"#);
        let _ = sibuna_json::write_string(&mut payload, &self.options.name);
        payload.push_str("}]");
        if let Some(replaced) = self.replaced() {
            payload.push_str(r#","replaces":"#);
            let _ = sibuna_json::write_string(&mut payload, replaced);
        }
        payload.push('}');
        payload
    }

    /// The payload that registers the account, or finds it when the key is known.
    fn registration(&self) -> String {
        let mut payload = String::from(r#"{"termsOfServiceAgreed":true"#);
        if let Some(binding) = &self.options.binding {
            let url = &self.endpoints.new_account;
            payload.push_str(r#","externalAccountBinding":"#);
            payload.push_str(&binding.bind(&self.account.key, url));
        }
        if let Some(email) = &self.options.email {
            payload.push_str(r#","contact":["#);
            let _ = sibuna_json::write_string(&mut payload, &format!("mailto:{email}"));
            payload.push(']');
        }
        payload.push('}');
        payload
    }

    /// Takes the response to the last request and returns the next action.
    pub fn advance(&mut self, response: Response) -> Action {
        if self.is_over() || self.phase == Phase::Present {
            return self.fail(unexpected("a response arrived that no request asked for"));
        }
        if response.body.len() > MAX_BODY {
            return self.fail(unexpected("its body exceeds 128 KiB"));
        }
        if let Some(nonce) = &response.nonce {
            if !is_token(nonce) {
                return self.fail(unexpected("its nonce is malformed"));
            }
            self.nonce = Some(nonce.clone());
        }
        if response.status >= 400 {
            let (word, error) = problem(&response);
            return match word.as_str() {
                // RFC 8555, section 6.5: repeat the request with the nonce of the error.
                "badNonce" if self.nonce.is_some() => self.send(),
                // The authority has not yet seen that the authorization is valid.
                "orderNotReady" if self.phase == Phase::Finalize => {
                    self.wait(response.retry_after)
                }
                // The authority does not take the certificate as one to replace: it
                // was replaced before, or it belongs to another account. The order is
                // placed again without the member.
                _ if self.phase == Phase::NewOrder
                    && self.replaced().is_some()
                    && self.nonce.is_some() =>
                {
                    self.options.replaces = None;
                    self.send()
                }
                _ if self.phase == Phase::Account && self.options.binding.is_some() => {
                    self.fail(Error::binding(error.message))
                }
                _ => self.fail(error),
            };
        }
        match self.accept(&response) {
            Ok(action) => action,
            Err(error) => self.fail(error),
        }
    }

    fn accept(&mut self, response: &Response) -> Result<Action, Error> {
        match self.phase {
            Phase::Directory => self.on_directory(response),
            Phase::Nonce => {
                if self.nonce.is_none() {
                    return Err(unexpected("it sent no nonce"));
                }
                let registered = self.account.url.is_some();
                Ok(self.enter(if registered { Phase::NewOrder } else { Phase::Account }))
            }
            Phase::Account => {
                let location = response.location.as_deref().unwrap_or_default();
                self.account.url = Some(self.checked_url(location)?);
                Ok(self.enter(Phase::NewOrder))
            }
            Phase::NewOrder => self.on_new_order(response),
            Phase::Authorization | Phase::PollAuthorization => self.on_authorization(response),
            Phase::Respond => {
                self.phase = Phase::PollAuthorization;
                Ok(self.wait(response.retry_after))
            }
            Phase::Finalize | Phase::PollOrder => self.on_order(response),
            Phase::Download => self.on_certificate(response),
            Phase::Present | Phase::Done | Phase::Failed => {
                Err(unexpected("a response arrived that no request asked for"))
            }
        }
    }

    /// Moves to `phase` and sends its request.
    fn enter(&mut self, phase: Phase) -> Action {
        debug_assert!(phase >= self.phase, "an order moves forward only");
        self.phase = phase;
        self.polls = 0;
        self.send()
    }

    /// Asks the caller to wait before the next poll: what the authority asked for, at
    /// most 30 seconds, or else 1, 2, 4 and then 8 seconds.
    fn wait(&mut self, retry_after: Option<u64>) -> Action {
        let own = 1u64 << self.polls.min(3);
        self.polls += 1;
        Action::Wait(retry_after.map_or(own, |seconds| seconds.clamp(1, MAX_WAIT)))
    }

    fn on_directory(&mut self, response: &Response) -> Result<Action, Error> {
        let value = object(&response.body)?;
        let members = value.as_object().ok_or_else(|| unexpected("no directory"))?;
        self.endpoints = Endpoints {
            new_nonce: self.checked_url(member(members, "newNonce")?)?,
            new_account: self.checked_url(member(members, "newAccount")?)?,
            new_order: self.checked_url(member(members, "newOrder")?)?,
            renewal_info: members.get("renewalInfo").and_then(Value::as_str).is_some(),
        };
        let meta = members.get("meta").and_then(Value::as_object);
        let required = meta.and_then(|meta| meta.get("externalAccountRequired"));
        let unbound = self.account.url.is_none() && self.options.binding.is_none();
        if unbound && required.and_then(Value::as_bool) == Some(true) {
            return Err(Error::binding(format!(
                "The authority {} registers an account only with an external account \
                 binding, and the file has none for it.",
                self.options.directory
            )));
        }
        Ok(self.enter(Phase::Nonce))
    }

    fn on_new_order(&mut self, response: &Response) -> Result<Action, Error> {
        let value = object(&response.body)?;
        let members = value.as_object().ok_or_else(|| unexpected("no order"))?;
        self.order_url = self.checked_url(response.location.as_deref().unwrap_or_default())?;
        self.finalize_url = self.checked_url(member(members, "finalize")?)?;
        let authorizations = members.get("authorizations").and_then(Value::as_array);
        let [authorization] = authorizations.unwrap_or_default() else {
            return Err(unexpected("an order for one name has one authorization"));
        };
        self.authorization_url = self.checked_url(authorization.as_str().unwrap_or_default())?;
        Ok(self.enter(Phase::Authorization))
    }

    fn on_authorization(&mut self, response: &Response) -> Result<Action, Error> {
        let value = object(&response.body)?;
        let members = value.as_object().ok_or_else(|| unexpected("no authorization"))?;
        let challenges = members.get("challenges").and_then(Value::as_array).unwrap_or_default();
        match (member(members, "status")?, self.phase) {
            ("valid", _) => Ok(self.enter(Phase::Finalize)),
            ("pending", Phase::Authorization) => self.choose(challenges),
            ("pending" | "processing", _) => {
                self.phase = Phase::PollAuthorization;
                Ok(self.wait(response.retry_after))
            }
            (status, _) => {
                let ours = self.challenge.as_ref().map(|challenge| challenge.kind.word());
                let failed = challenges.iter().filter_map(Value::as_object).find(|challenge| {
                    challenge.get("type").and_then(Value::as_str) == ours
                        && challenge.contains_key("error")
                });
                Err(Error::validation(format!(
                    "The authority could not validate `{}` ({}, authorization {}): {}",
                    self.options.name,
                    ours.unwrap_or("no challenge"),
                    printable(status, 32),
                    failed.map_or_else(|| "no reason given".to_owned(), reason)
                )))
            }
        }
    }

    /// Picks the challenge to answer among those the authority offers.
    fn choose(&mut self, challenges: &[Value<'_>]) -> Result<Action, Error> {
        let offered = |kind: ChallengeKind| {
            challenges.iter().take(MAX_CHALLENGES).filter_map(Value::as_object).find(|challenge| {
                challenge.get("type").and_then(Value::as_str) == Some(kind.word())
            })
        };
        let wanted = self.options.challenge;
        let (kind, found) = match offered(wanted) {
            Some(found) => (wanted, found),
            None => match offered(wanted.other()).filter(|_| self.options.any_challenge) {
                Some(found) => (wanted.other(), found),
                None => {
                    return Err(Error::validation(format!(
                        "The authority offers no `{}` challenge for `{}`.",
                        wanted.word(),
                        self.options.name
                    )));
                }
            },
        };
        let token = member(found, "token")?;
        if !is_token(token) {
            return Err(unexpected("a challenge token is malformed"));
        }
        self.challenge_url = self.checked_url(member(found, "url")?)?;
        let challenge = Challenge {
            kind,
            name: self.options.name.clone(),
            token: token.to_owned(),
            key_authorization: format!("{token}.{}", self.account.thumbprint()),
        };
        self.challenge = Some(challenge.clone());
        self.phase = Phase::Present;
        Ok(Action::Present(challenge))
    }

    /// The caller published the challenge answer: tell the authority.
    pub fn presented(&mut self) -> Action {
        if self.phase != Phase::Present {
            return self.fail(unexpected("no challenge is waiting to be presented"));
        }
        self.enter(Phase::Respond)
    }

    /// The wait is over: poll again.
    pub fn resume(&mut self) -> Action {
        if !matches!(self.phase, Phase::PollAuthorization | Phase::Finalize | Phase::PollOrder) {
            return self.fail(unexpected("the order is not waiting"));
        }
        self.send()
    }

    fn on_order(&mut self, response: &Response) -> Result<Action, Error> {
        let value = object(&response.body)?;
        let members = value.as_object().ok_or_else(|| unexpected("no order"))?;
        match member(members, "status")? {
            "valid" => {
                self.certificate_url = self.checked_url(member(members, "certificate")?)?;
                Ok(self.enter(Phase::Download))
            }
            "processing" | "ready" | "pending" => {
                self.phase = Phase::PollOrder;
                Ok(self.wait(response.retry_after))
            }
            status => Err(Error::refused(format!(
                "The authority ended the order for `{}` as {}: {}",
                self.options.name,
                printable(status, 32),
                reason(members)
            ))),
        }
    }

    fn on_certificate(&mut self, response: &Response) -> Result<Action, Error> {
        let chain = std::str::from_utf8(&response.body)
            .ok()
            .filter(|text| text.contains("-----BEGIN CERTIFICATE-----"))
            .ok_or_else(|| unexpected("the certificate is not a PEM chain"))?;
        let key = self.key.take().ok_or_else(|| unexpected("no key was generated"))?;
        self.phase = Phase::Done;
        Ok(Action::Done(Box::new(Issued { chain_pem: chain.to_owned(), key })))
    }
}

/// Runs one order to its end with a caller that may block: `send` performs a request,
/// `present` publishes a challenge answer, and `wait` sleeps for the given seconds. The
/// one-call path beside [`Order`].
pub fn obtain(
    account: &mut Account,
    options: OrderOptions,
    mut send: impl FnMut(&Request) -> Result<Response, Error>,
    mut present: impl FnMut(&Challenge) -> Result<(), Error>,
    mut wait: impl FnMut(u64),
) -> Result<Issued, Error> {
    let (mut order, mut action) = Order::begin(account, options);
    loop {
        action = match action {
            Action::Send(request) => order.advance(send(&request)?),
            Action::Present(challenge) => {
                present(&challenge)?;
                order.presented()
            }
            Action::Wait(seconds) => {
                wait(seconds);
                order.resume()
            }
            Action::Done(issued) => return Ok(*issued),
            Action::Failed(error) => return Err(error),
        };
    }
}

#[cfg(test)]
mod tests;
