# pv-server — the PlasmoVoice server for Horizon

> This crate is published on its own, inside the `plasmo-voice-rust` workspace;
> the *game* it talks to is the Horizon engine, which lives in a separate
> repository. [`../README.md`](../README.md) is the overview, the installation
> guide and the `[voice]` configuration reference; this file is the relay's own
> documentation.

The server half of PlasmoVoice: a **relay**, not a mixer. It hands every player
a secret and the shared AES key, and forwards the audio each player sends to the
ones within earshot. It never decodes audio and never decrypts it: every client
holds the same key, so the sealed payload travels through untouched and only the
16-byte secret in the datagram header is rewritten for each listener
(`UdpPacket::replace_secret`).

Written for `horizon-client`'s hosted world (a dedicated server or a LAN host),
against the protocol the Rust client port in `../client` already speaks and
`plasmo-voice-2.1.17` defines. No `tokio`, no async runtime: one thread, one
`std::net::UdpSocket`, and two bounded queues (a mutex and a condvar) to the
game.

Nothing is unbounded: positions coalesce on the way in, a full command queue
drops the oldest entry, a full event queue drops the oldest packet, a client
over its datagram budget is cut off, an oversized datagram is refused before it
is parsed, and a session that says nothing for `session_timeout` is let go.

## Files

```
src/lib.rs      the public API (Relay, Config, Event, Position) and what is missing
src/relay.rs    the thread: socket loop, session table, forwarding, keys, limits
src/session.rs  one player: secret, RSA key, mute state, distances, budget
src/crypto.rs   IV || AES/CBC/PKCS5, for the frames the relay seals itself
src/mutes.rs    voice_mutes.json: Java's JsonMuteStorage format, read and written
src/languages.rs the catalogue: Java's VoiceServerLanguages, Crowdin aside
languages/*.toml en_us.toml (the plugin's own) and ru_ru.toml, compiled in
src/tests.rs    a mock client over a real UDP socket (51 tests)
```

## What the server does

| Step | Wire | Here |
|---|---|---|
| The server asks first | `PlayerInfoRequest` in `plasmo:voice/v2`, 5 asks backing off 2, 4, 8, 8 s | `Worker::join`, `Worker::sweep`, `session::backoff` |
| The client answers with its RSA key | `PlayerInfo` (X.509 `SubjectPublicKeyInfo`) | `Worker::control` → `RsaPublicKey::from_public_key_der` |
| The server hands out the secret and the address | `Connection`: the secret, `0.0.0.0` ("use the Minecraft server's host", as Java's `[host] ip` default says) and the UDP port | `Worker::control` |
| The client's first datagram | `Ping` (`UDP_MAGIC`, secret), answered with nothing | `Worker::datagram` |
| Keep-alive | the server pings each session every 1.5–3 s (`NettyUdpKeepAlive`); the client's answers are what keep the session alive | `Worker::keepalive` |
| The server answers with the config | `Config` + `PlayerList` (two payloads, see below) | `Worker::configure` |
| A client without the mod is kicked | nothing on the wire: the player sends no payload at all, and the game disconnects them after `voice-client-mod-required-timeout` (Java's `ModRequiredKickHandler`, 3 s) | `Worker::join`, `Worker::channel` (any packet settles the check), `Worker::sweep` → `Event::ModMissing` |
| The client's language | `LanguageRequest` → `Language`: the name is the one the client asked for (or `defaultLanguage` when it asked for nothing), and the strings are the `[client]` scope of the `languages` file for it — `forcedLanguage` wins over the name, and an unknown language falls back to the default | `Worker::control`, `Catalogue::client` |
| The server's own words | the mute notice and the mod-required kick are `pv.mutes.*`/`pv.error.mod_missing_kick_message` rendered from the `[server]` scope in the language the recipient's client is set to (`ClientInformation.language`, Java's `holder.language`); a key the file does not have is left as a component for the client | `Catalogue::server`, `server_strings`/`translated` in `game/voice.rs` |
| Audio | `PlayerAudio` → `SourceAudio`, `secret` rewritten per listener | `Worker::audio`, `Worker::fill_listeners` |
| End of a burst | `PlayerAudioEnd` → `SourceAudioEnd` | `Worker::control` |
| Who is behind a source | `SourceInfoRequest` → `SourceInfo` (a `PLAYER` source) | `Worker::control` |
| Learning the sources before their audio | `SourceInfo` (`PLAYER`) to everyone configured, at every config | `Worker::configure` |
| The speaker's own state | `SelfAudioInfoPacket` (0x04) per frame, `SelfSourceInfoPacket` when the activation changes | `Worker::audio` |
| A server mute | `/vmute <player> [5m|permanent] [reason]`, `/vunmute <player|uuid>`, `/vmutelist` on the engine's console (Java's `pv.mute`/`pv.mutelist`), every word from the `[server]` scope — `pv.command.mute.*`, `pv.command.unmute.*`, `pv.command.mute_list.*` and the `expiration_date`/`expiration_time` patterns — in the console's language (`defaultLanguage`; a console has none of its own): `Muted Alice for 5 min. Reason: …`, `Alice, expires: 2026.11.04 at 22:24:36. Reason: …`; the muted player's audio is dropped and every `PlayerInfoUpdate` says `muted: true`, which is the icon `HIDE_SERVER_MUTED` hides | `Relay::mute`/`Relay::unmute` → `Worker::mute`, `Worker::broadcast_info`, `Event::Mute` (`until` is what the list prints) |
| Mutes that outlive a restart | `voice_mutes.json`, the name and the shape Java's `JsonMuteStorage` writes (`mutedToTime` is unix ms, `0` for never); read at start, written on every change by a thread of its own | `mutes::load`/`mutes::save`, `Saver`, `Worker::restore` |
| Silence | no datagram for `session_timeout` (15 s, PlasmoVoice's `keepAliveTimeoutMs`) | `Worker::sweep` |
| Reconnect | a second `PlayerInfo` re-keys the session: a new secret, a new `Connection`, a new key wrapped for the new RSA key | `Worker::control` |

Two protocol details that cost time and are easy to get wrong:

- **The config and the player list cannot share a payload.** `ConfigPacket`'s
  reader takes *anything* after the config as the optional `playerIconConfig`
  (2.1.7+), so a `PlayerListPacket` appended to it is read as an icon config and
  the whole payload fails. They go out as two payloads.
- **The config only comes after the first datagram.** The client opens its
  socket on `ConnectionPacket` and pings at once; the Java server sends the
  config when it hears from an unknown secret, and this relay does the same. It
  also proves the UDP path works before a client is told to use it.
- **The server pings, and never answers a ping.** The Java client pings on its
  own only until its socket is up, then waits for the server's pings and calls
  itself timed out after seven seconds without one — a server that never pings
  costs every Java player a dropped and re-keyed session every `session_timeout`.
  Answering a client's ping is no substitute: both clients answer a ping they
  receive, so an answer to an answer ping-pongs until the datagram rate limit
  starts dropping audio. Java answers none (`NettyUdpServerConnection.handle(
  PingPacket)` only records the time) and this relay matches it.

## Hooking it into the engine

Three source changes in `horizon-client` (the fork tree carries them, and
`native-mods/fork/apply.py` reproduces them on a fresh stage):

| File | Change |
|---|---|
| `crates/horizon-client/src/game/voice.rs` | new: the adapter — starts the relay, pushes positions once a second, posts its packets, answers the channel |
| `crates/horizon-client/src/game.rs` | `mod voice;` |
| `crates/horizon-client/src/game/lan_actions.rs` | `S::CustomPayload` arm for `plasmo:voice/v2` |
| `crates/horizon-client/src/game/dedicated.rs` | `voice::start(&props)` before the loop, `self.voice_tick()` after each `tick_server_timed` |
| `crates/horizon-client/Cargo.toml` | `pv-server` and `pv-proto` path dependencies |

The tick never blocks: `Relay::join`/`positions`/`channel` only queue a message,
`Relay::drain` only takes what is waiting, and the socket lives on the
`horizon-voice` thread. A packet for a player who has left is dropped.

## Configuration

The owner edits `[voice]` in `server.toml`; `horizon-server` renders it into
`server.properties` before every start, and the engine reads it back through
`horizon-server-files::voice` (the keys are spelled in exactly one place, so
the writer and the reader cannot drift):

```toml
[voice]
enabled = true               # voice-enabled
port = 25566                 # voice-port          (UDP; never the Minecraft port, that one is TCP)
mtu = 1024                   # voice-mtu-size      (bytes; 128..=5000)          Java: mtuSize
sample_rate = 48000          # voice-sample-rate   (8000/16000/24000/48000)     Java: sampleRate
opus_mode = "VOIP"           # voice-opus-mode     (VOIP/AUDIO/RESTRICTED_LOWDELAY)
opus_bitrate = -1000         # voice-opus-bitrate  (-1000 auto, -1 max, 500..=512000)
distances = [8, 16, 32]      # voice-distances     (blocks; 1..=64 each)       Java: proximity.distances
default_distance = 16        # voice-default-distance                           Java: proximity.defaultDistance
max_distance = 32            # voice-max-distance  (Horizon's own cap; Java has none)
extra_broadcast_distance = 16 # voice-extra-broadcast-distance (0..=64)        Java: maxExtraAudioBroadcastDistance
session_timeout = 15         # voice-session-timeout (seconds; 5..=600)        Java: keepAliveTimeoutMs / 1000
player_icon_visibility = []  # voice-player-icon-visibility                   Java: playerIcon.visibility
player_icon_y_offset = 0.0   # voice-player-icon-y-offset                     Java: playerIcon.yOffset
client_mod_min_version = "2.0.0" # voice-client-mod-min-version                Java: clientModMinVersion
notify_muted = true          # voice-notify-muted  (tell a player `/vmute` hit them) Java: [notifications] muted
notify_unmuted = true        # voice-notify-unmuted                             Java: [notifications] unmuted
default_language = "en_us"    # voice-default-language  (a client that asks for nothing gets these) Java: defaultLanguage
forced_language = ""         # voice-forced-language   (empty: each client's own)                  Java: forcedLanguage
key = ""                     # voice-key           (32 hex characters; empty: a new key each start)
```

Every one of them is used, not just stored: `mtu`/`sample_rate` go into
`CaptureInfo`, `opus_*` into its `encoder` (`{mode, bitrate}`, the shape the
Java server writes), `distances`/`default_distance` into the proximity
activation (default validated the way `validateDefaultDistance` does it),
`player_icon_*` into the optional `playerIconConfig` tail, `max_datagram_bytes`
is derived from `mtu` (plus 64 bytes of header and padding), and a client whose
`PlayerInfo.version` is below `client_mod_min_version` is never configured —
the log says `is older than 2.0.0; not configured`, exactly the Java behaviour
of not kicking it but not connecting it either.

`HORIZON_VOICE_PORT` and `HORIZON_VOICE_IP` remain as overrides for a launcher
that starts the engine with no `server.properties` of its own; `0` turns voice
off. A port that is already taken is a `WARN` in the log and the server runs
without voice, never a panic.

## Languages

Java's `VoiceServerLanguages` keeps a `languages` folder beside the config, one
TOML file per language, and answers a `LanguageRequest` with the `[client]`
scope of one, flattened into `pv.activation.proximity`-style keys. The relay
does the same, with the two files it ships compiled in:

```
languages/en_us.toml   Java's own file, key for key, `[server]` scope and all
languages/ru_ru.toml   the same in Russian (Java downloads it from Crowdin)
```

The engine points the relay at `languages/`, beside `server.properties`
(`LANGUAGES_DIR` in `game/voice.rs`), and the first start writes both files
there — **only the ones that are not there yet**, so an edited file is never
overwritten. Every `.toml` in the folder is then merged over the compiled-in
strings, key by key: a key the owner's file names replaces the shipped one, a
key it leaves out keeps it, and a language the relay does not ship is added as
it is (Java's `fillMissing` fills the gaps from `en_us`). A file that does not
parse is a `WARN` and skipped; the relay still starts.

Which file a client is answered from is Java's chain: `forcedLanguage` when it
is set (and nothing at all when it names a language there is no file for), else
the language the client asked for, else `defaultLanguage`, else `en_us`. The
name echoed back is always the client's own choice — Java sends
`requestedLanguage` there too (`PlayerChannelHandler.sendLanguage`) — so a
forced language changes the words without telling the client it speaks another
one.

The strings land where the mod has no translation of its own: Java's client
only consults the server's map for a key its resource pack does not have
(`ClientTextConverter`, `LanguageUtil.has`). `pv.activation.proximity` is such
a key for an activation the server registers, which is why it is the only
`[client]` entry the plugin ships.

The `[server]` scope is what the server says itself, and it is read: Java hands
it to the platform translator, which renders a `translate` component in the
recipient's language before sending it (`ServerLanguages.translate`). The engine
does the same for the two messages it sends a player — the mute notice
(`pv.mutes.*`) and the kick for a client without the mod
(`pv.error.mod_missing_kick_message`) — with `Catalogue::server` resolving the
language by Java's rule (`forcedLanguage`, else the client's own language from
`ClientInformation`, else `defaultLanguage`). The kick is why this matters:
the player being disconnected has no mod, so a component left for the client
would show it a raw key instead of the download link. A key the file does not
have is still left as a component, as Java leaves it.

The console reads the same scope. `/vmute`, `/vunmute` and `/vmutelist` render
`pv.command.*` and `pv.error.player_not_found` from it in `defaultLanguage` —
what Java's `getServerLanguage(null)` answers for a command source that is not
a player — and a deadline is spelled by the file's own
`pv.command.mute_list.expiration_date`/`expiration_time` patterns, so an owner
who edits `languages/<code>.toml` finds the feedback in the same file as the
notice a muted player gets.

Crowdin is not downloaded. Java caches a zip of translations in
`languages/.crowdin` for three days; a relay that fetched files at start would
be the only thing in the engine doing network I/O outside the game's sockets,
and `ru_ru.toml` ships here instead. `voice-use-crowdin-translations` therefore
has no key of its own: add a file to the folder and it is used.

## Testing

```sh
cd pv-voice && cargo test -p pv-server        # 52 tests, a real UDP socket each
```

The tests drive what a Java client does: the request, a real 1024-bit key, the
connection, a ping, the config (whose AES key only that client's private key
unwraps), then audio that reaches a listener 5 blocks away under *that
listener's* secret, is dropped at 40 blocks and across dimensions, is dropped
from a muted client, and stops when the session goes quiet. On top of that: a
re-key issues a new secret and kills the old one, a flood is cut off at the
datagram budget, an oversized datagram is refused, the command queue coalesces
positions and keeps the newest commands, and the key requests back off. The
P2 half: a `STATIC` source answers `SourceInfoRequest` with its record (place
included), a frame for it is sealed with the shared key and reaches only the
sessions near *it*, a rotation hands every configured session a new `Config`
under its own RSA key (and a client that joins after it starts on the new key),
and the crypto module round-trips `IV || AES/CBC/PKCS5` against a plain reader.

End to end, with the client fork built (`--features device`) and a dedicated
server from the same tree:

1. `HORIZON_VOICE_PORT=25566 cargo run --release -p horizon-client -- --dedicated --nogui --port 25565`
   → the log gets `voice: relay on 0.0.0.0:25566 (udp)`.
2. Join with the voice client (`127.0.0.1:25565`), open the voice menu: the log
   then has `voice: <name> joined the voice server`, `voice: <name> is configured`.
3. A Java client with PlasmoVoice 2.1.17 joins the same server and speaks; both
   sides hear each other, and the speaker icon follows `PlayerAudioEnd`.
4. Two clients 40 blocks apart say nothing to each other; walk back inside the
   activation distance (8/16/32, the config's proximity activation) and the
   audio returns.

## What is still missing

- **No producer for non-player sources yet.** The relay has the plumbing —
  `Relay::sources` (the `STATIC`/`ENTITY` records plus where each is heard) and
  `Relay::source_audio` (an Opus frame the relay seals and routes by the
  source's place) — but the engine has nothing to feed it: the sounds a jukebox
  or a mod plays are assets on the game's side, and turning them into Opus
  frames needs an encoder the server does not have. `game/voice.rs` therefore
  pushes no sources today; when something does, the client side already works
  (`SourceInfoRequest` → `SourceAudio`).
- Entity sources additionally need the game's entity ids and each entity's
  place, which `Relay::sources` takes as a plain `Place` and would be fed from
  the tick.
- The host player of a LAN world is not in `Hub::guests`, so the host is not
  heard yet (guests are).
- No stereo capture (the config advertises mono), no per-activation sections in
  the client's menu, no `SERVICE_CHANNEL` proxy support.
- Rotating `voice-key` now works without a restart: the engine watches
  `server.properties` on its own thread (every 2 s, never in the tick) and the
  relay re-sends each session a `Config` with the new key. The supervisor
  rewrites that file from `server.toml` at every start, so change `[voice] key`
  there too; an empty key is random per start and cannot be rotated to.
- Per-player voice permissions and per-activation source lines: the config
  grants `pv.activate` to everyone and offers only the `proximity` line and
  activation Java registers, with Java's own icons
  (`plasmovoice:textures/icons/speaker.png` and `microphone.png`). Those are
  full resource locations on purpose: a client parses the icon string as one,
  and a short name renders as the missing-texture checkerboard.
- What the Java config has and this port does not (a TODO rather than a
  silent default):
  - `pv.bypass_mod_requirement` as a *permission*: `clientModRequired` is
    implemented — a player who sends nothing is reported (`Event::ModMissing`)
    and the engine kicks them — and the engine spares an operator, which is
    what Java's undeclared permission amounts to on a Bukkit server. There is
    no permission system to grant it to anyone else; `voice-client-mod-required
    = false` still turns the whole check off.
  - Legacy `&` colour codes, which `no_permissions` in Java's file uses: the
    rendered messages are plain text, so an owner's `&c` would show as it is.
    Java's file only uses one for a message a console never sees styled.
  - `useCrowdinTranslations`: Java downloads a zip of translations into
    `languages/.crowdin` every three days (see Languages above); a relay ships
    `en_us` and `ru_ru` and reads the folder, so there is no key for it.
  - `checkForUpdates`: the engine is updated with the rest of Horizon
    (`horizon-server update`), not by the voice relay.
  - Who muted a player (`mutedByPlayerUUID` in Java's record): a Horizon server
    mutes from its console, which is not a player, so the file holds `null`
    there and the reason but no "muted by Steve".
  - A mute of a player who is offline: `/vmute` resolves a name among the
    joined players, as Java's `getPlayerByName` does, so a name that is not
    online is `pv.error.player_not_found`, from the file. `/vunmute` takes a
    UUID too, so a mute read
    back from `voice_mutes.json` can be lifted before its player joins again
    (the name the list shows for them is that UUID).
  - `/vmute … 5u` (Java's `MUTE_DURATION_UNIT.TIMESTAMP`): the absolute unix
    time is accepted, but the player and the confirmation are told `for 5 min`
    where Java divides the stamps; `/vmutelist` prints the end itself, as
    `expires: 2026.11.04 at 22:24:36` (`never` for a permanent mute), with
    Java's `pv.command.mute_list.*` wording.
  - `[voice.weights]` and the client menu's ordering: the client's own
    defaults; weights are only sent by a server that has several activations.
  - `[host] forwardingSecret`, `[host.public] ip/port` and `port = 0` (share
    the Minecraft port): the relay needs its own UDP socket, and there is no
    BungeeCord/Velocity forwarding.
  - `[voice.aesEncryptionKey]` as a config key: the key is `voice-key` here,
    spelled once in `horizon-server-files`.
  - `serverId` persisted in a file: it is a stable name-based UUID
    (`name_uuid("horizon:voice")`), so a client's per-server settings survive
    a restart just as they do with the Java plugin.
- The `activations[].distances` list is what `voice.distances` says, cut at
  `voice-max-distance` and sorted (`offered_distances`), with
  `default_distance` validated against it: the menu offers exactly those.
- A listener hears `min(distance + extra_broadcast_distance, distance * 2)`
  blocks, as `VoiceServerProximitySource.getListeners` computes it, so a
  16-block activation reaches 32 blocks. A source registered with distance `0`
  is a direct one and is heard by every session in its dimension.
