// ©AngelaMos | 2026
// event.rs

use std::fmt;
use std::net::SocketAddr;

use serde::Serialize;

use crate::fingerprint::{Ja3, Ja4Family};

/// A fingerprint produced by one direction of one flow, without addressing.
///
/// The protocol layer emits these; the pipeline wraps them with the flow's
/// addresses and timestamp to make a [`FingerprintEvent`]. Keeping the two
/// layers apart means the protocol extractor can be tested with bare byte
/// streams, no packets required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamEvent {
    ClientHello {
        ja3: Ja3,
        ja3_raw: String,
        ja4: Ja4Family,
        sni: Option<String>,
        alpn: Option<String>,
    },
    ServerHello {
        ja3s: Ja3,
        ja3s_raw: String,
        ja4s: Ja4Family,
    },
    Certificate {
        ja4x: String,
    },
    HttpRequest {
        ja4h: Ja4Family,
        method: String,
        host: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
    },
    TcpSyn {
        ja4t: String,
    },
    TcpSynAck {
        ja4ts: String,
    },
}

/// One fingerprint observation, addressed and timestamped.
///
/// `src` is always the party that sent the fingerprinted bytes: the client
/// for a ClientHello or SYN, the server for a ServerHello or certificate.
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintEvent {
    pub ts_nanos: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    #[serde(flatten)]
    pub event: StreamEvent,
}

impl fmt::Display for FingerprintEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.ts_nanos / 1_000_000_000;
        let millis = self.ts_nanos % 1_000_000_000 / 1_000_000;
        write!(f, "{secs}.{millis:03} {} -> {} ", self.src, self.dst)?;
        match &self.event {
            StreamEvent::ClientHello {
                ja3,
                ja4,
                sni,
                alpn,
                ..
            } => {
                write!(f, "client_hello ja4={} ja3={ja3}", ja4.hash)?;
                if let Some(sni) = sni {
                    write!(f, " sni={sni}")?;
                }
                if let Some(alpn) = alpn {
                    write!(f, " alpn={alpn}")?;
                }
                Ok(())
            }
            StreamEvent::ServerHello { ja3s, ja4s, .. } => {
                write!(f, "server_hello ja4s={} ja3s={ja3s}", ja4s.hash)
            }
            StreamEvent::Certificate { ja4x } => write!(f, "certificate ja4x={ja4x}"),
            StreamEvent::HttpRequest {
                ja4h,
                method,
                host,
                user_agent,
            } => {
                write!(f, "http_request ja4h={} method={method}", ja4h.hash)?;
                if let Some(host) = host {
                    write!(f, " host={host}")?;
                }
                if let Some(user_agent) = user_agent {
                    write!(f, " ua={user_agent}")?;
                }
                Ok(())
            }
            StreamEvent::TcpSyn { ja4t } => write!(f, "tcp_syn ja4t={ja4t}"),
            StreamEvent::TcpSynAck { ja4ts } => write!(f, "tcp_syn_ack ja4ts={ja4ts}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FingerprintEvent, StreamEvent};

    #[test]
    fn json_shape_is_tagged_and_flat() {
        let event = FingerprintEvent {
            ts_nanos: 1_500_000_000,
            src: "10.0.0.1:40000".parse().unwrap(),
            dst: "10.0.0.2:443".parse().unwrap(),
            event: StreamEvent::Certificate {
                ja4x: "7d5dbb3783b4_ba7ce0880c07_7bf9a7bf7029".into(),
            },
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "certificate");
        assert_eq!(json["ja4x"], "7d5dbb3783b4_ba7ce0880c07_7bf9a7bf7029");
        assert_eq!(json["src"], "10.0.0.1:40000");
    }

    #[test]
    fn display_is_one_greppable_line() {
        let event = FingerprintEvent {
            ts_nanos: 1_234_000_000,
            src: "10.0.0.1:40000".parse().unwrap(),
            dst: "10.0.0.2:443".parse().unwrap(),
            event: StreamEvent::TcpSyn {
                ja4t: "64240_2-1-3-1-1-4_1460_8".into(),
            },
        };
        assert_eq!(
            event.to_string(),
            "1.234 10.0.0.1:40000 -> 10.0.0.2:443 tcp_syn ja4t=64240_2-1-3-1-1-4_1460_8"
        );
    }
}
