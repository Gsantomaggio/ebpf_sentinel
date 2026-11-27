//! Protocol validation with TypeSafe's Jev model.
//!
//! The kernel hands us the first bytes of every new connection. Here they are sent to Jev, which
//! answers one yes/no question per known protocol ("do these bytes start an MQTT CONNECT?").
//! Jev only makes the judgments; what to do with them lives in [`decide`], a plain function that
//! compares the identified protocol with the one expected on the destination port.
//!
//! All question wording is in [`questions`] so it can be audited and edited in one place.

use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal as _;
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::validator::{Connection, Validator, Verdict, ascii_of, hex_of};

const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A Noul at or above this reads as "yes".
pub const YES_THRESHOLD: f64 = 0.7;
/// A Noul at or below this reads as "no". Between the two, the bytes don't settle the question.
pub const NO_THRESHOLD: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Amqp091,
    Amqp10,
    Mqtt,
    Http,
    RabbitStream,
    Tls,
}

impl Protocol {
    pub const ALL: [Protocol; 6] = [
        Protocol::Amqp091,
        Protocol::Amqp10,
        Protocol::Mqtt,
        Protocol::Http,
        Protocol::RabbitStream,
        Protocol::Tls,
    ];

    /// Question id; also what shows up in logs.
    pub fn id(self) -> &'static str {
        match self {
            Protocol::Amqp091 => "amqp_0_9_1",
            Protocol::Amqp10 => "amqp_1_0",
            Protocol::Mqtt => "mqtt",
            Protocol::Http => "http",
            Protocol::RabbitStream => "rabbitmq_stream",
            Protocol::Tls => "tls",
        }
    }
}

/// The protocols a destination port is expected to carry. `None` = no expectation, so the
/// connection is only reported, never flagged.
pub fn expected_protocols(port: u16) -> Option<&'static [Protocol]> {
    match port {
        // RabbitMQ serves both AMQP versions on the same listener.
        5672 => Some(&[Protocol::Amqp091, Protocol::Amqp10]),
        1883 => Some(&[Protocol::Mqtt]),
        5552 => Some(&[Protocol::RabbitStream]),
        15672 => Some(&[Protocol::Http]),
        // TLS listeners of the same services.
        5671 | 8883 | 5551 | 15671 => Some(&[Protocol::Tls]),
        _ => None,
    }
}

/// What Jev concluded about the bytes, from the per-protocol probabilities.
#[derive(Debug, Clone, PartialEq)]
pub enum Identified {
    /// Exactly one protocol reads as yes.
    One(Protocol, f64),
    /// More than one protocol reads as yes.
    Several(Vec<Protocol>),
    /// Nothing reads as yes, but at least one answer sits between the thresholds.
    Undecided,
    /// Every answer reads as no.
    Unrecognized,
}

pub fn identify(p: &BTreeMap<Protocol, f64>) -> Identified {
    let yes: Vec<(Protocol, f64)> = p
        .iter()
        .filter(|(_, v)| **v >= YES_THRESHOLD)
        .map(|(k, v)| (*k, *v))
        .collect();
    match yes.as_slice() {
        [(proto, v)] => Identified::One(*proto, *v),
        [] if p.values().any(|v| *v > NO_THRESHOLD) => Identified::Undecided,
        [] => Identified::Unrecognized,
        many => Identified::Several(many.iter().map(|(k, _)| *k).collect()),
    }
}

/// The truth table: (what the bytes are) x (what the port should carry) -> verdict.
pub fn decide(port: u16, identified: &Identified) -> Verdict {
    let expected = expected_protocols(port);
    match (identified, expected) {
        (Identified::One(proto, _), Some(exp)) if exp.contains(proto) => Verdict::Ok,
        (Identified::One(proto, p), Some(exp)) => Verdict::Suspicious(format!(
            "port {port} should carry {} but the bytes look like {} (p={p:.2})",
            names(exp),
            proto.id()
        )),
        (Identified::One(..), None) => Verdict::Ok,
        (Identified::Several(found), Some(exp)) if found.iter().all(|f| exp.contains(f)) => {
            Verdict::Ok
        }
        (Identified::Several(found), _) => {
            Verdict::Suspicious(format!("ambiguous: bytes read as {}", names(found)))
        }
        (Identified::Undecided, _) => {
            Verdict::Suspicious("inconclusive: no protocol is a clear match".into())
        }
        (Identified::Unrecognized, Some(exp)) => Verdict::Suspicious(format!(
            "port {port} should carry {} but the bytes match no known protocol",
            names(exp)
        )),
        (Identified::Unrecognized, None) => Verdict::Ok,
    }
}

fn names(ps: &[Protocol]) -> String {
    ps.iter().map(|p| p.id()).collect::<Vec<_>>().join("/")
}

/// How a connection is shown in the log, so a correct protocol stands out from a wrong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The protocol is the one expected on the port.
    Match,
    /// The port has no expectation, so there is nothing to compare with.
    Unchecked,
    /// A different protocol, or none at all, where one was expected.
    Mismatch,
    /// Jev was not sure, or more than one protocol matched.
    Unsure,
}

pub fn classify(port: u16, identified: &Identified, verdict: &Verdict) -> Status {
    match verdict {
        Verdict::Ok if expected_protocols(port).is_some() => Status::Match,
        Verdict::Ok => Status::Unchecked,
        Verdict::Suspicious(_) => match identified {
            Identified::Undecided | Identified::Several(_) => Status::Unsure,
            _ => Status::Mismatch,
        },
    }
}

/// Printed above every per-connection line so entries are easy to tell apart.
const ENTRY_SEPARATOR: &str = "────────────────────────────────────────────────";

impl Status {
    /// Icon and label, wrapped in bold ANSI colour when `color` is set.
    pub fn badge(self, color: bool) -> String {
        let (code, text) = match self {
            Status::Match => ("1;32", "✅ MATCH   "),
            Status::Unchecked => ("1;34", "ℹ️  UNCHECKED"),
            Status::Mismatch => ("1;31", "❌ MISMATCH"),
            Status::Unsure => ("1;33", "⚠️  UNSURE  "),
        };
        if color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
    }
}

/// Wrap `text` in the ANSI colour `code` when `color` is set.
fn paint(text: &str, code: &str, color: bool) -> String {
    if color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
}

fn describe(identified: &Identified) -> String {
    match identified {
        Identified::One(p, v) => format!("{} (p={v:.2})", p.id()),
        Identified::Several(ps) => format!("several: {}", names(ps)),
        Identified::Undecided => "inconclusive".into(),
        Identified::Unrecognized => "no known protocol".into(),
    }
}

/// Every question sent to Jev. Each asks for one judgment about `first_bytes`.
mod questions {
    use super::*;

    /// (instructions, what a yes means, what a no means)
    fn wording(p: Protocol) -> (&'static str, &'static str, &'static str) {
        match p {
            Protocol::Amqp091 => (
                "Do `first_bytes` begin with the AMQP 0-9-1 protocol header?",
                "The bytes are the ASCII letters AMQP followed by the bytes 00 00 09 01",
                "The bytes start with anything else, including AMQP followed by other version bytes",
            ),
            Protocol::Amqp10 => (
                "Do `first_bytes` begin with an AMQP 1.0 protocol header?",
                "The bytes are the ASCII letters AMQP followed by 00 01 00 00 (plain AMQP 1.0) \
                 or by 03 01 00 00 (AMQP 1.0 SASL)",
                "The bytes start with anything else, including AMQP followed by 00 00 09 01",
            ),
            Protocol::Mqtt => (
                "Do `first_bytes` look like the start of an MQTT CONNECT packet?",
                "The first byte is 10, followed by a length byte, then 00 04 and the ASCII \
                 letters MQTT (or 00 06 and MQIsdp for MQTT 3.1)",
                "The bytes do not start with an MQTT CONNECT packet",
            ),
            Protocol::Http => (
                "Do `first_bytes` look like the start of an HTTP/1.x request?",
                "The bytes are an HTTP method written in ASCII, such as GET, PUT, POST, DELETE, \
                 HEAD or OPTIONS, followed by a space and the start of a path",
                "The bytes are not readable HTTP request text",
            ),
            Protocol::RabbitStream => (
                "Do `first_bytes` look like the start of a RabbitMQ Stream protocol frame?",
                "A 4-byte big-endian frame length is followed by the command key 00 11 and the \
                 version 00 01 (the peer properties request), with mostly non-text bytes",
                "The bytes are readable text, or do not follow that frame layout",
            ),
            Protocol::Tls => (
                "Do `first_bytes` look like the start of a TLS ClientHello record?",
                "The first byte is 16, the second is 03, the third is 01, 02 or 03, and a record \
                 length follows",
                "The bytes do not start with a TLS handshake record",
            ),
        }
    }

    pub fn build() -> Value {
        let mut qs = serde_json::Map::new();
        for p in Protocol::ALL {
            let (instructions, yes, no) = wording(p);
            qs.insert(
                p.id().into(),
                json!({
                    "type": "noul",
                    "instructions": instructions,
                    "criteria": { "true": yes, "false": no },
                }),
            );
        }
        Value::Object(qs)
    }

    /// What a person would look at: the bytes as text and as hex, nothing else. The destination
    /// port is deliberately left out so it can't sway the answer; code compares it afterwards.
    pub fn state(conn: &Connection) -> Value {
        json!({
            "context": "The first bytes a TCP client sent to a server right after connecting.",
            "first_bytes": {
                "byte_count": conn.first_bytes.len(),
                "ascii_with_dots_for_unprintable": ascii_of(&conn.first_bytes),
                "hex": hex_of(&conn.first_bytes),
            },
        })
    }
}

#[derive(Deserialize)]
struct Response {
    answers: HashMap<String, Answer>,
}

#[derive(Deserialize)]
struct Answer {
    noul: Option<f64>,
}

/// Parse a Jev response into one probability per protocol. A missing answer is an error, not a "no".
fn probabilities(resp: Response) -> anyhow::Result<BTreeMap<Protocol, f64>> {
    Protocol::ALL
        .iter()
        .map(|p| {
            let v = resp
                .answers
                .get(p.id())
                .and_then(|a| a.noul)
                .with_context(|| format!("jev response has no noul answer for `{}`", p.id()))?;
            Ok((*p, v))
        })
        .collect()
}

pub struct JevValidator {
    http: reqwest::Client,
    api_key: String,
    model: String,
    /// ANSI colours in the log line: only on a terminal, and never when `NO_COLOR` is set.
    color: bool,
}

impl JevValidator {
    pub fn new(api_key: String, model: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the HTTP client")?;
        let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Ok(Self { http, api_key, model, color })
    }

    /// The exact payload sent for a connection (logged at debug level, never includes the key).
    fn payload(&self, conn: &Connection) -> Value {
        json!({
            "model": self.model,
            "state": questions::state(conn),
            "questions": questions::build(),
        })
    }
}

impl Validator for JevValidator {
    async fn validate(&self, conn: &Connection) -> anyhow::Result<Verdict> {
        if conn.first_bytes.is_empty() {
            // Nothing to judge; do not spend a request on it.
            return Ok(Verdict::Ok);
        }
        let payload = self.payload(conn);
        log::debug!("jev request: {payload}");
        let resp = self
            .http
            .post(ENDPOINT)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
            .context("sending the request to jev")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("jev returned {status}: {body}");
        }
        let resp: Response = resp.json().await.context("decoding the jev response")?;
        let probs = probabilities(resp)?;
        let identified = identify(&probs);
        let summary: Vec<String> = probs.iter().map(|(p, v)| format!("{}={v:.2}", p.id())).collect();
        let port = conn.dst.1;
        let verdict = decide(port, &identified);
        let status = classify(port, &identified, &verdict);
        let expected = expected_protocols(port).map_or("any".to_owned(), names);
        let expected = paint(&expected, "1;35", self.color);
        log::info!(
            "\n\n{ENTRY_SEPARATOR}\n{} {} -> {}: detected {} | port {port} expects {expected} [{}]",
            status.badge(self.color),
            std::net::SocketAddr::new(conn.src.0, conn.src.1),
            std::net::SocketAddr::new(conn.dst.0, conn.dst.1),
            paint(&describe(&identified), "1;36", self.color),
            summary.join(" ")
        );
        Ok(verdict)
    }
}

/// Read the API key: `TYPESAFE_API_KEY` wins, otherwise the first non-empty line of `path`.
/// The file may hold the bare key or a `NAME=key` line. The key is never logged.
pub fn load_api_key(path: &std::path::Path) -> anyhow::Result<String> {
    if let Ok(key) = std::env::var("TYPESAFE_API_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            return Ok(key.to_owned());
        }
    }
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "--enable_jev needs an API key: set TYPESAFE_API_KEY or provide {}",
            path.display()
        )
    })?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .with_context(|| format!("{} is empty", path.display()))?;
    let key = line.rsplit('=').next().unwrap_or(line).trim().trim_matches(['"', '\'']);
    if key.is_empty() {
        bail!("{} does not contain an API key", path.display());
    }
    Ok(key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probs(vals: [f64; 6]) -> BTreeMap<Protocol, f64> {
        Protocol::ALL.iter().copied().zip(vals).collect()
    }

    #[test]
    fn single_yes_is_identified() {
        let p = probs([0.01, 0.02, 0.97, 0.0, 0.01, 0.0]);
        assert_eq!(identify(&p), Identified::One(Protocol::Mqtt, 0.97));
    }

    #[test]
    fn middle_band_is_undecided() {
        let p = probs([0.5, 0.1, 0.1, 0.0, 0.0, 0.0]);
        assert_eq!(identify(&p), Identified::Undecided);
    }

    #[test]
    fn all_low_is_unrecognized() {
        assert_eq!(identify(&probs([0.01; 6])), Identified::Unrecognized);
    }

    #[test]
    fn truth_table() {
        let mqtt = Identified::One(Protocol::Mqtt, 0.99);
        let amqp = Identified::One(Protocol::Amqp091, 0.99);
        assert_eq!(decide(1883, &mqtt), Verdict::Ok);
        assert!(matches!(decide(5672, &mqtt), Verdict::Suspicious(_)));
        assert_eq!(decide(5672, &amqp), Verdict::Ok);
        assert_eq!(decide(9999, &mqtt), Verdict::Ok);
        assert!(matches!(decide(5672, &Identified::Unrecognized), Verdict::Suspicious(_)));
        assert_eq!(decide(9999, &Identified::Unrecognized), Verdict::Ok);
        assert!(matches!(decide(5672, &Identified::Undecided), Verdict::Suspicious(_)));
        // both AMQP versions on one listener is fine; AMQP + MQTT is ambiguous.
        let both = Identified::Several(vec![Protocol::Amqp091, Protocol::Amqp10]);
        assert_eq!(decide(5672, &both), Verdict::Ok);
        let mixed = Identified::Several(vec![Protocol::Amqp091, Protocol::Mqtt]);
        assert!(matches!(decide(5672, &mixed), Verdict::Suspicious(_)));
    }

    #[test]
    fn status_tells_correct_from_wrong() {
        let ok = |port, id: Identified| classify(port, &id, &decide(port, &id));
        let mqtt = Identified::One(Protocol::Mqtt, 0.9);
        assert_eq!(ok(1883, mqtt.clone()), Status::Match);
        assert_eq!(ok(5672, mqtt.clone()), Status::Mismatch);
        assert_eq!(ok(9999, mqtt), Status::Unchecked);
        assert_eq!(ok(5672, Identified::Unrecognized), Status::Mismatch);
        assert_eq!(ok(5672, Identified::Undecided), Status::Unsure);
        let mixed = Identified::Several(vec![Protocol::Amqp091, Protocol::Mqtt]);
        assert_eq!(ok(5672, mixed), Status::Unsure);
    }

    #[test]
    fn badge_colors_only_when_asked() {
        assert!(!Status::Match.badge(false).contains('\x1b'));
        assert!(Status::Mismatch.badge(true).starts_with("\x1b[1;31m"));
        assert!(Status::Match.badge(true).starts_with("\x1b[1;32m"));
    }

    #[test]
    fn missing_answer_is_an_error() {
        let resp: Response = serde_json::from_str(r#"{"answers":{"mqtt":{"noul":0.9}}}"#).unwrap();
        assert!(probabilities(resp).is_err());
    }

    #[test]
    fn key_file_formats() {
        let dir = std::env::temp_dir().join(format!("jev-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in [("bare", "abc123\n"), ("named", "export TYPESAFE_API_KEY=\"abc123\"\n")] {
            let f = dir.join(name);
            std::fs::write(&f, body).unwrap();
            // SAFETY: no other test in this module reads this variable.
            unsafe { std::env::remove_var("TYPESAFE_API_KEY") };
            let key = load_api_key(&f).unwrap();
            assert!(key.ends_with("abc123"), "{name}: {key}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
