//! The server half of PlasmoVoice, for a Horizon server.
//!
//! A PlasmoVoice server is a relay: it hands each player a secret and a shared
//! AES key, and forwards the audio each player sends to the ones close enough
//! to hear it. It never decodes audio and never decrypts it — every client
//! holds the same key, so the sealed payload travels through untouched and
//! only the 16-byte secret in the datagram header is rewritten for the
//! listener (`UdpPacket::replace_secret`).
//!
//! Two transports, like the Java server ([`pv_proto`]):
//!
//! * the control packets, inside the plugin channel [`CHANNEL`] of the
//!   Minecraft connection: the game hands every payload to
//!   [`Relay::channel`] and sends back what [`Relay::drain`] returns;
//! * the audio datagrams, on the relay's own UDP socket.
//!
//! Nothing here runs on the game's thread: [`Relay::start`] puts the socket
//! and the session table on a thread of their own, and the two sides talk
//! through two bounded queues (a mutex and a condvar, not `mpsc`, which cannot
//! drop). Every call the game makes is non-blocking, and [`Relay::drain`] never
//! waits, so a tick can call it every tick.
//!
//! Nothing is unbounded either: a full command queue keeps the newest commands
//! (positions coalesce, so a hundred ticks leave one snapshot), a full event
//! queue drops the oldest, a session that floods is cut off at
//! [`Config::datagrams_per_second`], a datagram over
//! [`Config::max_datagram_bytes`] is refused before it is parsed, and a session
//! that says nothing for [`Config::session_timeout`] is let go.
//!
//! The pieces the server does not do yet are listed in
//! `server-plugin/VOICE-BRIDGE.md` §5 and at the end of this file.

mod crypto;
mod languages;
mod mutes;
mod relay;
mod session;
#[cfg(test)]
mod tests;

pub use languages::Catalogue;
pub use pv_proto::Uuid;
pub use relay::{
    Config, Event, Level, MuteDuration, MuteUnit, Place, Position, Relay, Source,
};

/// The plugin channel the control packets travel in.
pub const CHANNEL: &str = pv_proto::CHANNEL;

/// The secret a session is handed, as the 16 bytes the header carries.
pub fn secret() -> Uuid {
    use rsa::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A Minecraft player's UUID (`Guest::uuid` in `horizon-client`) as the
/// 16 bytes the protocol writes. Big-endian, as Java's `UUID` fields are.
pub fn uuid_of(player: u128) -> Uuid {
    player.to_be_bytes()
}

// What this server does not do yet, and why (VOICE-BRIDGE.md §5):
//
// * no producer for the non-player sources it can now carry: `Relay::sources`
//   and `Relay::source_audio` route a `STATIC`/`ENTITY` record and the frames
//   aimed at it, but a game sound is an asset on the client and turning one
//   into an Opus frame needs an encoder the server does not have;
// * no per-player volume: PV keeps it on the client (`volume` in the client's
//   config) and the server only carries the distances;
// * no stereo switch: `PlayerAudio.stereo` is forwarded only in the sense
//   that the bytes are untouched, and the config advertises mono capture;
// * no proxy: `SERVICE_CHANNEL` (`plasmo:voice/v2/service`) is what a proxy
//   would use to hand out its own key, and a relay does not need it.
