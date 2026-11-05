# Horizon PlasmoVoice — Rust port

**Native proximity voice chat for Horizon servers, written in Rust.**

[![build](https://github.com/pipapupa228lox-oss/plasmo-voice-rust/actions/workflows/build.yml/badge.svg)](https://github.com/pipapupa228lox-oss/plasmo-voice-rust/actions/workflows/build.yml)
[![license: LGPL-3.0](https://img.shields.io/badge/license-LGPL--3.0-blue.svg)](LICENSE)
[![Minecraft: 26.3](https://img.shields.io/badge/Minecraft-26.3-green.svg)](#compatibility)
[![PlasmoVoice: 2.1.x](https://img.shields.io/badge/PlasmoVoice-2.1.x-orange.svg)](#compatibility)

This repository is a from-scratch Rust implementation of the [PlasmoVoice](https://github.com/plasmoapp/plasmo-voice)
2.1.x protocol — the voice mod for Minecraft — with two halves:

- **`pv-client`** — the client side: the `plasmo:voice/v2` handshake, RSA/AES
  cryptography, the Opus codec and the audio devices.
- **`pv-server`** — the server side: the UDP relay, sessions, server mutes and
  the language catalog.

Both speak the same wire format as the Java plugin, so a Java PlasmoVoice client
can use a Horizon server, and a Horizon client can use a Java PlasmoVoice
server. The playable pieces are built into Horizon: the client side is compiled
into the game by the launcher (a native `.hnmod` bundle), and the server side
runs inside the dedicated server (`horizon-client --dedicated`).

## Why a port

The Java mod has to run inside a JVM-hosted Minecraft server; Horizon's server is
a single native binary with no async runtime and no plugin sandbox that could
host it. The wire protocol is self-contained, though, and a Rust relay is a
natural fit: the server forwards sealed Opus frames and never decodes audio, so
it costs a fraction of what a Java plugin costs to run next to the world tick.

## Features

- **Proximity voice** — every player picks an activation distance (8, 16 or 32
  blocks by default); the relay only forwards a speaker's frames to listeners
  whose range covers them. A distance of `0` is a *direct* source and reaches
  the whole dimension (used for radio/static sources).
- **A relay, not a mixer** — the server never decodes, re-encodes or decrypts
  audio. It rewrites the 16-byte session secret in each datagram header and
  forwards the sealed payload, so CPU time goes into routing, not into PCM.
- **Opus at 48 kHz** — 20 ms frames, configurable mode (`VOIP`, `AUDIO`,
  `RESTRICTED_LOWDELAY`) and bitrate; the frame is sized to the negotiated MTU.
- **Encryption** — each session generates an RSA-2048 key (X.509
  `SubjectPublicKeyInfo`); the server wraps a 16-byte AES key for it with
  `RSA/ECB/PKCS1Padding`. Audio payloads are `AES/CBC/PKCS5` with the IV in
  front, and only the payload: the header stays clear so the relay can route it.
- **Server administration** — `/vmute`, `/vunmute`, `/vmutelist` on the server
  console, mutes that survive a restart (`voice_mutes.json`, the same file
  format as the Java plugin), a mod-required kick with a timeout, and a shared
  key that can be rotated without restarting.
- **Localised** — `languages/<code>.toml` beside `server.properties`, split
  into the `[client]` scope (sent to the mod) and the `[server]` scope (the
  words the server itself prints). Player-facing messages are rendered in the
  player's own Minecraft language; the console speaks `default_language`.
- **Built for a game tick** — no async runtime: std threads, `Arc` snapshots and
  bounded queues (drop-oldest) between the tick and the relay, with one position
  snapshot a second and at most 256 packets drained per tick.
- **Launcher integration** — ships as a `.hnmod` native mod, compiled by
  `horizon-launcher` for the exact Horizon revision the player runs.

## Compatibility

| | Horizon server (this relay) | Java Paper + PlasmoVoice 2.1.17 |
|---|---|---|
| **Horizon client** (this code) | yes | yes |
| **Java client** (PlasmoVoice 2.1.x) | yes | yes |

Checked against the Java sources of PlasmoVoice 2.1.17 — packet ids, the UDP
header (`0x4e9004e9`, id, secret, millis), `IV || AES/CBC/PKCS5`, the config
fields and the source/activation UUIDs (`nameUUIDFromBytes(name + "_line")`) are
byte for byte the same. Listening range is `min(distance + extra, distance * 2)`,
as `VoiceServerProximitySource.getListeners` computes it.

## Installation

### Server

Voice is part of the engine, not a plugin: `horizon-server` starts the engine,
and the engine opens the UDP socket.

```sh
horizon-server init --eula --world world --port 25565 --offline --no-whitelist --yes
horizon-server run          # the engine logs "voice: relay on 0.0.0.0:25566 (udp)"
```

Voice is on by default (`[voice] enabled = true` in `server.toml`). Open
**25566/udp** (or whatever `[voice] port` is) next to 25565/tcp — the client is
told which port to use, so only it has to be reachable.

The `horizon-server` supervisor writes the `[voice]` section into
`server.properties` as `voice-*` keys before every start; edit `server.toml`,
not `server.properties`, or the change is overwritten.

### Client

The client half is a native mod, which the launcher compiles into the game:

1. Install Horizon with the launcher (this port needs Horizon's native mod
   support and Minecraft 26.3).
2. **Mods** page → **PlasmoVoice** → *Install*, then turn it on. (A bundle can
   also be dropped into the instance's `horizon-native-mods/` folder as
   `<id>.hnmod` and enabled in the mod list.)
3. Build it: `horizon-launcher native-build --trust-native-code` — native mods
   are not sandboxed, so this confirms you trust their source.
4. Play the **Native mods** instance. In game, `/plugins` lists the bundle under
   *Loaded*.

Java players need nothing but the normal PlasmoVoice mod and the server
address.

## Configuration

Everything the Java mod's `config.toml` had is in one `[voice]` section of
`server.toml` (and reaches the engine as `voice-*` keys in
`server.properties`):

```toml
[voice]
enabled = true               # PlasmoVoice proximity chat, served by the engine over UDP
port = 25566                 # the voice port; open it next to 25565/tcp; 0 would share the Minecraft port, which this server cannot
mtu = 1024                   # the largest voice packet a client encodes, in bytes (PlasmoVoice: mtuSize)
sample_rate = 48000          # 8000, 16000, 24000 or 48000 (PlasmoVoice: sampleRate)
opus_mode = "VOIP"           # VOIP, AUDIO or RESTRICTED_LOWDELAY ([voice.opus] mode)
opus_bitrate = -1000         # -1000 auto, -1 max, or 500..512000 bits a second ([voice.opus] bitrate)
distances = [8, 16, 32]      # the distances a client may pick, in blocks (proximity.distances)
default_distance = 16        # the one it starts on (proximity.defaultDistance)
max_distance = 32            # Horizon's own cap on any activation
extra_broadcast_distance = 16 # blocks relayed past the activation distance, never past twice it (maxExtraAudioBroadcastDistance)
session_timeout = 15         # seconds of silence before a session is dropped (keepAliveTimeoutMs)
player_icon_visibility = []  # icons a client hides: HIDE_NOT_INSTALLED, HIDE_VOICE_CHAT_DISABLED, HIDE_SERVER_MUTED, HIDE_CLIENT_MUTED, HIDE_SOURCE_ICON
player_icon_y_offset = 0.0   # how far above the head the speaker icon sits ([voice.playerIcon] yOffset)
client_mod_min_version = "2.0.0" # a client older than this is not configured (clientModMinVersion)
client_mod_required = false   # true: players must have the mod, or they are kicked (clientModRequired)
client_mod_required_timeout = 3000 # ms they have to send the mod's first packet (clientModRequiredCheckTimeoutMs)
default_language = "en_us"    # the server's fallback language (defaultLanguage)
forced_language = ""         # one language for every client; empty: each client's own (forcedLanguage)
notify_muted = true          # tell a player when /vmute hits them (PlasmoVoice: [notifications] muted)
notify_unmuted = true        # and when they are unmuted (PlasmoVoice: [notifications] unmuted)
key = ""                     # 32 hex characters shared with the clients; empty: a new key each start
```

Notes:

- **`key`** — with an empty value the engine generates a fresh AES key at every
  start; clients get it wrapped with their own RSA key, so a shared secret is
  not needed for new sessions. A non-empty key can be rotated on a live server:
  the engine watches `server.properties` and re-sends every session its config
  within two seconds. Keep `[voice] key` in `server.toml` in sync, or the
  supervisor rewrites the file on the next start.
- **`client_mod_required`** — an operator is spared (Java's
  `pv.bypass_mod_requirement`, an undeclared plugin permission that a Bukkit
  server grants to operators). Everyone else is disconnected after
  `client_mod_required_timeout`.
- **`player_icon_visibility`** — the icons the *server* hides; a client's own
  menu can hide more.

### Moderation

Voice commands live on the server console (Java's `pv.mute`/`pv.mutelist`):

```
vmute Alice                  :: forever
vmute Alice 5m griefing      :: five minutes, with a reason
vmute Alice 30               :: no unit is seconds, as in Java
vunmute Alice                :: by name
vunmute 8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e6f   :: by UUID, offline players included
vmutelist
```

A muted player is dropped from every relay and is announced to the others with
`muted: true`, which is the icon `HIDE_SERVER_MUTED` hides. Mutes are stored in
`voice_mutes.json` next to `server.properties` — the same JSON the Java plugin
writes, so a file can be moved between the two.

### Languages

The server ships `en_us` (the Java plugin's own file, key for key) and `ru_ru`,
seeds them into `languages/` beside `server.properties`, and never overwrites a
file the owner edited. A language is just another `languages/<code>.toml`:

- `[client.pv.…]` — what a `LanguageRequest` is answered with; the mod uses it
  for keys its own resource pack does not have.
- `[server.pv.…]` — what the server says itself: the mute notice, the
  mod-required kick, `/vmute`'s feedback and `/vmutelist`, including the
  `expiration_date`/`expiration_time` patterns a deadline is printed with
  (`yyyy.MM.dd`, `HH:mm:ss`).

A key the file lacks is filled from `en_us`, as Java's `fillMissing` does.

## Building from source

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test      # libopus' CMakeLists predates CMake 4
cargo build --release --features device          # adds cpal for microphone and speakers
```

Requirements:

- A stable Rust toolchain (the port is built and tested with 1.95, edition 2021).
- CMake and a C toolchain — `audiopus` builds the bundled libopus from source.
  On Linux also install `libasound2-dev` for the `device` feature
  (`sudo apt-get install -y cmake build-essential libasound2-dev`).
- `CMAKE_POLICY_VERSION_MINIMUM=3.5` is only needed for CMake 4, which dropped
  compatibility with the `cmake_minimum_required(VERSION 3.x)` libopus still
  uses.

Features: `opus` (default) is the real codec; `device` adds `cpal` devices;
`--no-default-features` gives the crates without Opus, for tests that only need
the wire format.

### About the releases

CI builds the workspace for Linux and macOS (Windows is left out of the matrix
for now — the suite passes on Windows, the runner does not) and publishes, per
target, the release libraries (`libpv_proto`, `libpv_client`, `libpv_server`) and the
`dump_key` example (prints an X.509 public key as a Rust array — handy when
debugging a handshake). It does **not** publish a standalone voice server: the
relay is useless without the game telling it where the players are, so the
playable build is the engine's. Equally, the `.hnmod` bundle is compiled by the
launcher against the exact Horizon revision — that is what the *Installation*
section above installs.

### Repository layout

```
proto/     bytes.rs (Java semantics)  data.rs (records)  packets.rs (codecs)
client/    identity.rs  crypto.rs (AES + RSA)  session.rs (UDP)  state.rs (the handshake)
           codec.rs  audio.rs  device.rs
server/    relay.rs (sessions, proximity, mutes)  session.rs  crypto.rs  mutes.rs  languages.rs
```

[`server/README.md`](server/README.md) is the relay's own reference: what it
puts on the wire, how the engine drives it, and what is still missing.

The client side drives like this:

```rust
let mut session = VoiceSession::new("26.3");
session.set_server_address("play.example.org:25565"); // for a 0.0.0.0 announcement
session.handle_channel(payload)?;          // each plasmo:voice/v2 payload in
for packet in session.take_outgoing() { /* send on the channel */ }
session.feed_microphone(&samples)?;        // each 20 ms frame (960 samples at 48 kHz)
session.touch();                           // keep-alive, once a frame
for incoming in session.poll_audio() { mixer.push(incoming.source_id, incoming.samples) }
```

The server side is `Relay`: the game pushes player positions and channel
payloads, drains events, and posts the returned packets to the players'
Minecraft connections.

## How a session starts

Four details from the Java source decide whether a client can join at all:

1. **The plugin channel carries the control packets.** Their names say TCP, but
   no TCP socket is ever opened: `ConnectionPacket`, `ConfigPacket` and the rest
   arrive as payloads of `plasmo:voice/v2`, and the client's answers go back
   through the same channel.
2. **The server asks first.** `PlayerInfoRequest` is sent to everyone on join
   and retried five times (2, 4, 8, 8 s); the client must answer with its
   `PlayerInfo`, never before.
3. **`PlayerInfo` must carry a real RSA key.** The server parses it as X.509
   `SubjectPublicKeyInfo`; junk means no config and no voice.
4. **`Config` only comes after the client's first datagram.** The client opens
   its socket on `ConnectionPacket` and pings at once; the server answers an
   unknown secret with the config. It also proves the UDP path works.

## Tests

95 tests, all without a Minecraft install:

```sh
cargo test          # 30 client, 13 protocol, 52 server (real UDP sockets)
```

The protocol crate is tested byte for byte against the Java codecs; the client
handshake runs against a mock server over real UDP; the relay is driven by real
datagrams, signed with a real 1024-bit key.

## Known deviations

Client side, all deliberate:

- Occlusion is one raycast, not `SoundOcclusion`'s walk: a wall halves the
  volume (Java's first block), but two walls do not add.
- Stereo activations are not sent; the mixer pans positionally instead.
- The client pings every 500 ms; Java pings every second.
- `host.port = 0` ("share the Minecraft port") is not supported: the relay needs
  its own UDP port.

Server side: a mute has no "muted by" field (Horizon mutes from its console,
which is not a player, so the file stores `null` as Java does for the same
case), and `&` colour codes in a language file are printed as text.

## Contributing

Issues and pull requests are welcome. Before sending one:

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo test
cargo clippy --workspace --all-targets
```

The Java sources are the specification: a wire-format change that disagrees
with PlasmoVoice 2.1.17 is a bug, not an improvement. New packet fields need a
byte-level test in `proto`, and anything that touches the handshake should be
tried against a Java client (or server) at least once.

## Credits

This port would not exist without **[PlasmoVoice](https://github.com/plasmoapp/plasmo-voice)**
by **[Apehum](https://github.com/Apehum)** and the Plasmo team — the protocol,
the language files and the behaviour this code matches are theirs. The Java
2.1.17 sources were used as the specification throughout.

The game it plugs into is **Horizon**, a Rust rewrite of Minecraft 26.3, and
Minecraft itself is a trademark of Mojang Studios; no Mojang code, assets or
data are part of this repository.

## License

**[GNU Lesser General Public License v3.0](LICENSE)** (LGPL-3.0), the same
licence as the original PlasmoVoice. This project is a derived work: the wire
protocol, the constants and the language files come from PlasmoVoice 2.1.17,
and the Rust code here is a port of its behaviour.

Changes relative to the Java plugin: everything in this repository is rewritten
in Rust — no Java code is compiled or shipped — with a different internal
structure (std threads instead of Netty, a single relay thread, bounded queues
instead of an executor), a Rust implementation of TOML language files, and the
server mutes stored by a Rust JSON reader/writer. When distributing a modified
version, keep it under the LGPL and make the source available, as the licence
requires.

## По-русски

**Horizon PlasmoVoice** — нативный голосовой чат для Horizon (Minecraft 26.3 на
Rust), портированный с PlasmoVoice 2.1.17. Протокол совместим: Java-клиент
работает с этим сервером, этот клиент — с Java-сервером.

- **Сервер.** Релей живёт в движке, а не в плагине: `horizon-server` запускает
  `horizon-client --dedicated`, тот открывает UDP-порт (`[voice] port`, по
  умолчанию 25566, бандл `[voice]` в `server.toml`). Голос включён сразу.
- **Клиент.** `.hnmod`-бандл ставится лаунчером: страница **Mods** →
  PlasmoVoice → включить, затем `horizon-launcher native-build
  --trust-native-code` и играть в версии «Native mods».
- **Модерация.** `/vmute <ник> [5m|permanent] [причина]`, `/vunmute <ник|uuid>`,
  `/vmutelist` в консоли сервера; муты переживают перезапуск
  (`voice_mutes.json`, формат Java-плагина).
- **Языки.** `languages/<код>.toml` рядом с `server.properties`: `[client]` —
  строки моду, `[server]` — то, что говорит сам сервер (мут, кик, ответы
  консоли), с форматами даты `expiration_date`/`expiration_time`.
- **Лицензия.** LGPL-3.0 — та же, что у PlasmoVoice; порт является производным
  произведением.
