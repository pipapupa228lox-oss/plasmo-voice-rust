//! One player's voice session: the secret their datagrams carry, the RSA key
//! they announced, how recently they were heard, and how fast they may talk.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use pv_proto::{Uuid, VoicePlayerInfo};
use rsa::RsaPublicKey;

/// `PlayerInfoRequestScheduler`: the server asks a joining client for its key
/// this many times, then gives up.
pub const REQUESTS: u32 = 5;
/// The wait after the first ask, which is the Java server's own 2 seconds; it
/// doubles each time, up to [`REQUEST_MAX`].
pub const REQUEST_FIRST: Duration = Duration::from_secs(2);
/// The longest wait between asks. Five asks are 2+4+8+8 = 22 seconds: a client
/// that is still generating its 2048-bit key on a slow machine keeps getting
/// asked, and one whose Minecraft connection never loads is let go before the
/// session timeout takes it.
pub const REQUEST_MAX: Duration = Duration::from_secs(8);

/// How long to wait before ask number `requests` (1-based): 2, 4, 8, 8 s.
///
/// A client whose Minecraft connection is still loading answers the first ask
/// within a tick, so the early asks are close together; one that is stuck
/// behind a slow key generation gets room instead of five asks in ten seconds
/// that all arrive while it is still busy.
pub fn backoff(requests: u32) -> Duration {
    let doublings = requests.saturating_sub(1).min(2);
    (REQUEST_FIRST * (1 << doublings)).min(REQUEST_MAX)
}

/// A player on the voice server.
pub struct Session {
    pub player: Uuid,
    pub name: String,
    /// The 16 bytes the client's datagrams start with after the magic.
    pub secret: Uuid,
    /// `PlayerInfoPacket.publicKey`, once it parses as an X.509 RSA key.
    pub key: Option<RsaPublicKey>,
    /// `ConfigPacket` went out, which happens after the first datagram: the
    /// client opens its socket on `ConnectionPacket` and speaks at once.
    pub configured: bool,
    pub muted: bool,
    pub voice_disabled: bool,
    /// The distances the client hears each activation at
    /// (`PlayerActivationDistancesPacket`).
    pub distances: Vec<(Uuid, i32)>,
    /// The activation the last frame was sent on, for the `SelfSourceInfoPacket`
    /// the speaker gets when it changes (`SelfActivationHelper`).
    pub activation: Option<Uuid>,
    /// The size of the last sealed frame: the Java server sends the frame back
    /// to its speaker only when the encoder changed its packet size.
    pub sent_size: usize,
    /// Where its datagrams come from, once it has sent one.
    pub address: Option<SocketAddr>,
    pub last_seen: Instant,
    /// When the next `PingPacket` goes out.
    ///
    /// `NettyUdpKeepAlive` pings every connection on a 1.5–3 s schedule, and
    /// that ping is the only thing a Java client counts as proof the server is
    /// still there: it stops pinging on its own once its socket is up and
    /// declares itself timed out after seven seconds of silence, so a server
    /// that never pings costs every Java client a reconnect every few seconds.
    pub next_ping: Instant,
    /// How many `PlayerInfoRequestPacket`s went out, and when the next goes.
    pub requests: u32,
    pub next_request: Instant,
    /// `clientModRequiredCheckTimeoutMs`: the moment the player must have sent
    /// a control packet by, or `None` when no check is running (the setting is
    /// off, or the answer already came). Java's `ModRequiredKickHandler`
    /// schedules exactly this on the player's join.
    pub mod_check: Option<Instant>,
    /// Audio frames that reached the relay but nobody was close enough to
    /// hear; only for the log.
    pub dropped: u64,
    /// Datagrams refused by the budget below; only for the log.
    pub flooded: u64,
    /// The datagram budget, in datagrams: refilled up to a second's worth.
    tokens: f32,
    tokens_at: Instant,
}

impl Session {
    pub fn new(player: Uuid, name: &str, secret: Uuid, now: Instant) -> Self {
        Session {
            player,
            name: name.to_string(),
            secret,
            key: None,
            configured: false,
            muted: false,
            voice_disabled: false,
            distances: Vec::new(),
            activation: None,
            sent_size: 0,
            address: None,
            last_seen: now,
            next_ping: now,
            requests: 0,
            next_request: now,
            mod_check: None,
            dropped: 0,
            flooded: 0,
            // One datagram of credit, so the very first ping is never the one
            // that gets refused.
            tokens: 1.0,
            tokens_at: now,
        }
    }

    /// A `PlayerInfoRequestPacket` is due: the key has not arrived and the
    /// retries are not used up.
    pub fn wants_request(&self, now: Instant) -> bool {
        self.key.is_none() && self.requests < REQUESTS && now >= self.next_request
    }

    pub fn asked(&mut self, now: Instant) {
        self.requests += 1;
        self.next_request = now + backoff(self.requests);
    }

    /// A keep-alive ping is due: the session has an address to send it to and
    /// its turn has come. Like Java's, the ping is sent to the address the
    /// client's own datagrams come from, so it also opens the NAT mapping that
    /// the client's audio comes back through.
    pub fn wants_ping(&self, now: Instant) -> bool {
        self.address.is_some() && now >= self.next_ping
    }

    /// The ping went out: the next one is `after` from now.
    pub fn pinged(&mut self, now: Instant, after: Duration) {
        self.next_ping = now + after;
    }

    /// The retries are spent and there is still no key: nothing will come.
    pub fn gave_up(&self) -> bool {
        self.key.is_none() && self.requests >= REQUESTS
    }

    /// Charges one datagram to the session's budget, which refills at
    /// `per_second` and holds at most a second of it. `false` means this one
    /// arrived too fast and must not be relayed: one client uploading from a
    /// bad modem, or flooding on purpose, cannot spend everyone's bandwidth.
    ///
    /// A token bucket rather than a fixed window: audio is bursty (a talk
    /// spurt is 50 packets a second for two seconds, then silence), and a
    /// window that resets would let a burst cross the boundary.
    pub fn spend(&mut self, now: Instant, per_second: u32) -> bool {
        let rate = per_second.max(1) as f32;
        let elapsed = now.saturating_duration_since(self.tokens_at).as_secs_f32();
        self.tokens = (self.tokens + elapsed * rate).min(rate);
        self.tokens_at = now;
        if self.tokens < 1.0 {
            self.flooded += 1;
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    /// `ModRequiredKickHandler.handlePlayerJoin`: from now the player has
    /// `wait` to prove the mod is installed.
    pub fn expect_answer(&mut self, now: Instant, wait: Duration) {
        self.mod_check = Some(now + wait);
    }

    /// The check is over — the first control packet arrived, or the kick went
    /// out — so it fires once.
    pub fn settle_check(&mut self) {
        self.mod_check = None;
    }

    /// The player's time is up and the check has not run yet.
    pub fn overdue(&self, now: Instant) -> bool {
        self.mod_check.is_some_and(|deadline| now >= deadline)
    }

    pub fn touch(&mut self, now: Instant, address: SocketAddr) {
        self.last_seen = now;
        self.address = Some(address);
    }

    /// What `PlayerListPacket`/`PlayerInfoUpdatePacket` say about the player.
    ///
    /// `server_muted` is the server's own mute (`/vmute`), which is what
    /// `VoicePlayerInfo.muted` means in PlasmoVoice
    /// (`VoiceServerPlayerEntity.createPlayerInfo`: `getMute(id).isPresent()`).
    /// The player's microphone switch is a different field: `microphone_muted`.
    pub fn info(&self, server_muted: bool) -> VoicePlayerInfo {
        VoicePlayerInfo {
            player_id: self.player,
            nick: self.name.clone(),
            muted: server_muted,
            voice_disabled: self.voice_disabled,
            microphone_muted: self.muted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_requests_back_off_and_stop() {
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(2), Duration::from_secs(4));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(4), Duration::from_secs(8));
        // Whatever the ask number, the wait never exceeds the cap.
        assert_eq!(backoff(99), REQUEST_MAX);

        // The first ask goes out on join and the rest follow the schedule, so
        // the last one lands at 22 s — inside the default session timeout, and
        // a session that never answers is let go by `gave_up`.
        let total: Duration = (1..REQUESTS).map(backoff).sum();
        assert_eq!(total, Duration::from_secs(22));
        assert!(total < Duration::from_secs(30), "{total:?}");
    }

    #[test]
    fn a_session_is_pinged_once_it_has_an_address() {
        let start = Instant::now();
        let mut session = Session::new(*b"0123456789abcdef", "Alice", *b"fedcba9876543210", start);

        // Nothing to send to before the client has spoken.
        assert!(!session.wants_ping(start));

        session.touch(start, "127.0.0.1:41000".parse().expect("an address"));
        assert!(session.wants_ping(start), "the first ping is due at once");

        session.pinged(start, Duration::from_secs(2));
        assert!(!session.wants_ping(start + Duration::from_millis(1_999)));
        assert!(session.wants_ping(start + Duration::from_secs(2)));
    }

    #[test]
    fn the_mod_check_runs_out_once_and_any_packet_settles_it() {
        let start = Instant::now();
        let mut session = Session::new(*b"0123456789abcdef", "Alice", *b"fedcba9876543210", start);

        // No check until the relay is told to start one.
        assert!(!session.overdue(start + Duration::from_secs(60)));

        session.expect_answer(start, Duration::from_millis(3_000));
        assert!(!session.overdue(start + Duration::from_millis(2_999)));
        assert!(session.overdue(start + Duration::from_millis(3_000)));

        // A control packet cancels it (Java: `TcpPacketReceivedEvent`).
        session.settle_check();
        assert!(!session.overdue(start + Duration::from_secs(60)));

        // And so does the check itself, so one join is kicked at most once.
        session.expect_answer(start, Duration::from_millis(3_000));
        assert!(session.overdue(start + Duration::from_secs(4)));
        session.settle_check();
        assert!(!session.overdue(start + Duration::from_secs(5)));
    }

    #[test]
    fn a_burst_is_charged_against_the_budget_and_refills() {
        let start = Instant::now();
        let mut session = Session::new(*b"0123456789abcdef", "Alice", *b"fedcba9876543210", start);

        // A second's worth goes through, then the bucket is empty.
        let mut passed = 0;
        for _ in 0..50 {
            if session.spend(start, 50) {
                passed += 1;
            }
        }
        assert_eq!(passed, 1, "only the first datagram had credit");
        assert_eq!(session.flooded, 49);

        // 20 ms later there is room for one more at 50/s.
        let later = start + Duration::from_millis(20);
        assert!(session.spend(later, 50), "the budget refills with time");
    }
}
