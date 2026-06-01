# SPEC-ZAP-PQ-v1

**Status**: DRAFT
**Wire identifier**: `ZAP-PQ-v1`
**Ciphersuite registry byte**: `0x01`

This document specifies the wire format and state machine for the
native post-quantum transport of ZAP. The reference implementation in
`~/work/lux/zap/handshake/` and `~/work/lux/zap/conn_pq.go` is a
mechanical transcription of this spec.

---

## 1. Scope

ZAP-PQ-v1 wraps a TCP byte stream with a Noise-style hybrid
post-quantum handshake (X25519 + ML-KEM-768) and ML-DSA-65 identity,
deriving an AES-256-GCM AEAD session keyed per direction. It replaces
any TLS/Noise layer underneath ZAP — once ZPQ1 is negotiated, no other
crypto frame the TCP stream.

Out of scope: TCP framing, retransmission, congestion. ZAP-PQ-v1
assumes a reliable ordered byte stream and aborts on any out-of-order
event.

## 2. Notation

| Notation | Meaning |
|---|---|
| `u8`, `u16`, `u32`, `u64` | Unsigned big-endian integer (1, 2, 4, 8 bytes) |
| `[N]` | Fixed-size byte array of length N |
| `vec<u32>` | u32 BE length prefix, then that many payload bytes |
| `∥` | Concatenation |
| `||` | (in pseudo-code) "or" |
| Bytes are written as `0xHH`. |

All multi-byte integers on the wire are big-endian. There are no
alignment or padding rules — every field is byte-packed.

## 3. Constants

```
Magic prefix     : 0x5A 0x50 0x51 0x31              ("ZPQ1")
Protocol label   : "ZAP-PQ-v1"                       (9 bytes ASCII)
Ciphersuite ID   : 0x01

X25519           : PK_LEN  = 32
                   SK_LEN  = 32
                   SS_LEN  = 32

ML-KEM-768       : PK_LEN  = 1184
                   CT_LEN  = 1088
                   SS_LEN  = 32

ML-DSA-65        : PK_LEN  = 1952
                   SIG_LEN = 3309

AES-256-GCM      : KEY_LEN   = 32
                   NONCE_LEN = 12
                   TAG_LEN   = 16
                   SALT_LEN  = 4    (per-direction prefix of nonce)

SHA3-256         : OUT_LEN = 32

Replay window    : 30 seconds          (HELLO timestamp)
Replay cache TTL : 60 seconds          (server-side bloom)
PSK lifetime     : 3600 seconds        (resumption)
Rekey limit      : min(2^31 frames, 3600 seconds, 100 GB) per direction
```

### 3.1 Wire labels

Domain-separation strings used inside the KDF and transcript. ASCII,
no NUL terminator. Length-prefixed when concatenated into KDF input.

```
LBL_PROTOCOL    = "ZAP-PQ-v1"
LBL_X25519      = "X25519"
LBL_MLKEM       = "ML-KEM-768"
LBL_SESSION_I2R = "ZAP-PQ-v1 i->r"
LBL_SESSION_R2I = "ZAP-PQ-v1 r->i"
LBL_SALT_I2R    = "ZAP-PQ-v1 nonce-salt i->r"
LBL_SALT_R2I    = "ZAP-PQ-v1 nonce-salt r->i"
LBL_RESUMPTION  = "ZAP-PQ-v1 resumption"
LBL_REKEY       = "ZAP-PQ-v1 rekey"
LBL_AUTH_I      = "ZAP-PQ-v1 auth initiator"
LBL_AUTH_R      = "ZAP-PQ-v1 auth responder"
```

### 3.2 Ciphersuite registry

| ID | KEX | Sig | AEAD | Hash |
|---|---|---|---|---|
| `0x00` | reserved (never on the wire) | — | — | — |
| `0x01` | X25519 + ML-KEM-768 | ML-DSA-65 | AES-256-GCM | SHA3-256 |
| `0x02`–`0x7F` | reserved for upstream Lux suites (consensus team registers) |
| `0x80`–`0xFE` | reserved for downstream / white-label profiles (must register before claiming) |
| `0xFF` | reserved (never on the wire) |

A node that receives an unknown ciphersuite byte MUST respond with
ALERT code `0x02` (`unsupported_ciphersuite`) and close the
connection.

## 4. Handshake state machine

```
Initiator                                Responder
─────────                                ─────────
  │                                          │
  │ ────── MAGIC ∥ HELLO  ────────────►      │
  │                                          │
  │ ────── KEM_INIT ─────────────────►       │
  │                                          │
  │ ◄───── KEM_REPLY ───────────────         │
  │ ◄───── AUTH(role=R) ────────────         │
  │                                          │
  │ ────── AUTH(role=I) ────────────►        │
  │                                          │
  │ ═══════ AEAD session ═══════════════════ │
  │ ◄════► DATA / REKEY / ALERT ════════════ │
```

Every state transition is byte-driven. No timers other than the
handshake-completion timer (default 5 s) and the rekey timer.

Failure modes:
- malformed frame → ALERT `0x01` (`decode_error`), close
- unknown ciphersuite → ALERT `0x02`, close
- signature verify fail → ALERT `0x03` (`auth_failed`), close
- replay (timestamp or nonce) → ALERT `0x04` (`replay_detected`), close
- downgrade (peer omitted PQ scheme under StrictPQ) → ALERT `0x05`
  (`downgrade_refused`), close
- handshake timeout → ALERT `0x06` (`handshake_timeout`), close

## 5. Frame format

Every frame after the magic prefix has the same outer envelope:

```
struct Frame {
  type:    u8     // see §6
  length:  u32    // body length in bytes, BE
  body:    [length]byte
}
```

`length` MUST NOT exceed `2^24` (16 MiB). A larger value MUST trigger
ALERT `0x01` and close.

## 6. Frame layouts

### 6.0 Magic prefix (TCP byte stream prologue)

Before any frame, the initiator MUST send exactly:

```
0x5A 0x50 0x51 0x31    // "ZPQ1"
```

The responder reads four bytes. If they do not match, behaviour is
governed by the chain's `ChainSecurityProfile`:

- `StrictPQ` (`0x01`) or `FIPS` (`0x03`): close immediately, no
  ALERT (the peer isn't speaking ZAP-PQ).
- `Permissive` (`0x02`): fall through to legacy ZAP framing.

The magic is NOT included in the frame stream and NOT included in the
transcript hash.

### 6.1 HELLO (type=`0x01`)

Sent by initiator after the magic. Sole frame initiator sends before
KEM_INIT.

```
struct HELLO {
  ciphersuite:        u8           // §3.2; must be 0x01 for this spec
  pq_mode:            u8           // 0x00 classical-permitted
                                   // 0x01 pq-required
                                   // 0x02 pq-only
  client_random:      [16]         // CSPRNG, fresh each handshake
  timestamp_ns:       u64          // initiator's unix nanos
  client_id:          [32]         // SHA3-256(initiator_static_mldsa_pk)
  offered_schemes:    vec<u32>     // ordered list of u8 ciphersuite IDs
                                   // (e.g. for a hybrid offer: 0x01)
  static_pk_initiator: [PK_LEN]    // ML-DSA-65 public key (1952 B)
  // total wire: 1 + 1 + 16 + 8 + 32 + 4 + N + 1952  =  2014 + N
}
```

`offered_schemes` MUST be non-empty and MUST include `ciphersuite`.

`client_random` and `timestamp_ns` together protect against replay
(see §11). `client_id` MUST equal `SHA3-256(static_pk_initiator)` —
the responder enforces this binding to prevent UKS.

Responder MUST check `|now - timestamp_ns| ≤ 30 s` and MUST consult
its replay cache for `(client_id, client_random)`; on hit, ALERT
`0x04`.

### 6.2 KEM_INIT (type=`0x02`)

```
struct KEM_INIT {
  x25519_pk_eph:      [32]
  mlkem_pk_eph:       [1184]
}
```

Both ephemerals are freshly generated for this handshake. The
initiator MUST zero the corresponding ephemeral secret keys after
KEM_REPLY is processed (see §10).

### 6.3 KEM_REPLY (type=`0x03`)

Responder picks ML-KEM-768 encapsulation against
`mlkem_pk_eph` and an X25519 ephemeral of its own.

```
struct KEM_REPLY {
  x25519_pk_eph:        [32]       // responder's ephemeral X25519 pk
  mlkem_ct:             [1088]     // ML-KEM-768 ciphertext to initiator
  static_pk_responder:  [1952]     // responder's static ML-DSA-65 pk
}
```

The responder MUST verify the initiator's `client_id` matches
`SHA3-256(static_pk_initiator)` before sending KEM_REPLY. The
responder's own `static_pk_responder` is sent in this frame so the
initiator can verify it against the VM-identity binding (§10) and
include it in the transcript.

### 6.4 AUTH (type=`0x04`)

Each side signs its own role.

```
struct AUTH {
  role:        u8       // 0x49 'I' for initiator, 0x52 'R' for responder
  signature:   [3309]   // ML-DSA-65 signature
}
```

The signed message is:

```
sign_input(role) =
  LBL_PROTOCOL ∥ 0x00 ∥                            // domain separator
  ciphersuite_byte ∥ 0x00 ∥                        // suite binding
  H_2 ∥                                            // post-KEM transcript hash
  ( LBL_AUTH_I if role==0x49 else LBL_AUTH_R )     // role binding
```

The `0x00` bytes are domain-separator terminators. ML-DSA-65 is invoked
through `crypto/mldsa.SignCtx(sk, msg, ctx)` with `ctx = "lux-zap-pq-v1"`
so it cannot be cross-protocol replayed against P-Chain UTXO sigs or
the EVM precompile.

Responder sends its AUTH first (in the same TCP write as KEM_REPLY is
permitted but not required). Initiator MUST verify the responder's
AUTH against `static_pk_responder` from KEM_REPLY before sending its
own AUTH.

After both AUTH frames verify, the handshake is complete; subsequent
frames are DATA (encrypted) or control (REKEY, ALERT).

### 6.5 DATA (type=`0x05`)

```
struct DATA {
  nonce_counter:  u64                    // monotonic per direction
  ciphertext:     vec<u32>               // AES-256-GCM output + tag
}
```

The full 12-byte AES-GCM nonce is constructed from per-direction salt
+ counter (§9.2).

`length` field of the outer frame covers `8 + 4 + ciphertext_length`.

A receiver MUST hard-fail (ALERT `0x07` = `nonce_violation`, close) if
`nonce_counter` is not strictly greater than the last accepted counter
for that direction within the current epoch.

### 6.6 REKEY (type=`0x06`)

Either side MAY initiate. Body is one byte:

```
struct REKEY {
  reason:  u8     // 0x01 = counter-limit, 0x02 = time-limit,
                  // 0x03 = bytes-limit,   0x04 = explicit (admin)
}
```

Behaviour:

1. Sender finishes any DATA frames in flight under the current epoch.
2. Sender emits REKEY, increments its epoch byte, derives the next
   per-direction key via §13, zeroes the old key.
3. Sender resets its nonce_counter to 0 for the new epoch.
4. Receiver mirrors: on REKEY, derives the next key for the *sender's*
   direction, resets its expected counter. The receiver's own send
   direction is unaffected — each side rekeys independently.

REKEY's body itself travels unencrypted (it is a control frame). The
post-rekey DATA frames will not decrypt under the old key, so the
control frame is integrity-bound by the next AAD (which carries
`epoch`).

Mandatory rekey thresholds (per direction):
- `2^31` DATA frames sent, OR
- 3600 seconds since last rekey, OR
- `100 * 2^30` bytes plaintext sent.

A sender MUST emit REKEY before crossing any threshold. A receiver
that sees a `nonce_counter` ≥ `2^31` without a preceding REKEY MUST
ALERT `0x07` and close.

### 6.7 ALERT (type=`0x07`)

```
struct ALERT {
  code:     u8     // see §14
  detail:   vec<u32>   // optional human-readable string (UTF-8)
}
```

Sender closes the TCP connection immediately after the ALERT frame is
written. Receivers should log `code` and the first 256 bytes of
`detail`.

### 6.8 HELLO_PSK (type=`0x08`)

Resumption variant. Replaces HELLO + KEM_INIT in the resumed
handshake.

```
struct HELLO_PSK {
  ciphersuite:        u8
  pq_mode:            u8
  client_random:      [16]
  timestamp_ns:       u64
  psk_id:             [16]            // server-issued identifier
  x25519_pk_eph:      [32]            // fresh X25519 ephemeral
}
```

If the server recognises `psk_id` and it has not been redeemed and
has not expired (3600 s), the responder skips ML-KEM, derives a new
session via §12, and proceeds directly to AUTH. Otherwise it ALERTs
`0x08` (`psk_unknown`) and closes; the initiator falls back to a full
handshake by reconnecting.

## 7. Transcript construction

The transcript is a chain of SHA3-256 hashes accumulating every byte
of every handshake frame in send order:

```
H_0  = SHA3-256( LBL_PROTOCOL ∥ 0x00 ∥ ciphersuite_byte ∥ HELLO_bytes )
H_1  = SHA3-256( H_0 ∥ KEM_INIT_bytes ∥ KEM_REPLY_bytes )
H_2  = SHA3-256( H_1 ∥ static_pk_initiator ∥ static_pk_responder
                     ∥ offered_schemes_encoded )
```

Where:
- `HELLO_bytes` is the wire-encoded HELLO body (everything after the
  outer `type ∥ length`).
- `KEM_INIT_bytes` / `KEM_REPLY_bytes` likewise.
- `offered_schemes_encoded` is `len_u32 BE ∥ scheme_bytes` (the same
  byte sequence already inside HELLO; re-mixed in to make scheme-strip
  attacks detectable: a stripped scheme would compute a different
  `H_2` than what the signer signed, and AUTH verify would fail).
- `static_pk_initiator` is repeated from HELLO (binding) and
  `static_pk_responder` from KEM_REPLY.

`H_2` is the message hash the AUTH signature covers (§6.4).

For the resumption path (§6.8), the transcript collapses to:

```
H_0_psk = SHA3-256( LBL_PROTOCOL ∥ 0x00 ∥ ciphersuite_byte ∥ HELLO_PSK_bytes )
H_2_psk = SHA3-256( H_0_psk ∥ x25519_pk_eph_responder )
```

`H_2_psk` is then used by §12 as the KDF salt.

## 8. KDF

### 8.1 IKM construction

Length-prefix every label and every shared secret with a single `u8`
length byte (each individual field is ≤ 255 bytes; labels fit
trivially, shared secrets are exactly 32 bytes).

```
IKM = u8(len(LBL_X25519))  ∥ LBL_X25519  ∥ u8(SS_LEN) ∥ x25519_shared
    ∥ u8(len(LBL_MLKEM))   ∥ LBL_MLKEM   ∥ u8(SS_LEN) ∥ mlkem_shared
```

This is identical on both sides because both labels and lengths are
constants for `ZAP-PQ-v1` ciphersuite `0x01`.

### 8.2 Extract

```
PRK = HKDF-Extract(salt = H_2, IKM = IKM_from_8.1)
```

`H_2` is the post-AUTH transcript hash from §7. Using the transcript
hash as the HKDF salt binds the keys to the full handshake including
the offered scheme list and both static identities.

### 8.3 Expand — per-direction keys and nonce salts

```
k_i2r        = HKDF-Expand(PRK, LBL_SESSION_I2R, 32)
k_r2i        = HKDF-Expand(PRK, LBL_SESSION_R2I, 32)
salt_i2r     = HKDF-Expand(PRK, LBL_SALT_I2R,    4)
salt_r2i     = HKDF-Expand(PRK, LBL_SALT_R2I,    4)
resumption_psk = HKDF-Expand(PRK, LBL_RESUMPTION, 32)
```

Five expansions, all from the same PRK. Each side keeps its own send
key + send salt and its peer's receive key + receive salt.

### 8.4 Hash function

HKDF uses SHA3-256 (NOT SHA-256). This keeps the entire PQ path on
FIPS 202 hash primitives, aligning with Corona / Pulsar / Quasar.

## 9. AEAD

### 9.1 Cipher

AES-256-GCM (NIST SP 800-38D). Key is 32 bytes; nonce is 12 bytes;
tag is 16 bytes appended to ciphertext.

### 9.2 Nonce construction

```
nonce_full = salt_{dir} (4 B)  ∥  nonce_counter (8 B BE)
```

Where `salt_{dir}` is `salt_i2r` for initiator-to-responder traffic and
`salt_r2i` for responder-to-initiator. `nonce_counter` starts at 0 for
each new epoch and increments by 1 per DATA frame.

Counter wraparound is forbidden — sender MUST emit REKEY before
counter reaches `2^31` (§6.6).

### 9.3 Associated data (AAD)

```
AAD = frame_type (u8)
    ∥ length     (u32 BE)
    ∥ direction  (u8)   // 0x49 'I' for i->r, 0x52 'R' for r->i
    ∥ epoch      (u8)   // §13
```

`frame_type` MUST equal `0x05` (DATA) for any AEAD-wrapped frame —
control frames are never AEAD-wrapped, so they cannot be confused with
a different AAD-binding type.

Including `direction` in AAD prevents reflection: a frame the
initiator sent cannot be replayed back to the initiator as if it came
from the responder, because the receive direction's key differs and
the AAD's `direction` byte differs.

### 9.4 Encrypt / decrypt

```
ciphertext = AES-256-GCM-Encrypt(
  key   = k_{send_dir},
  nonce = nonce_full,
  aad   = AAD,
  plain = payload,
)
```

Decrypt is the inverse with `key = k_{recv_dir}`. A failed tag check
MUST trigger ALERT `0x03` (`auth_failed`) and close.

## 10. Identity binding

### 10.1 Static identities

Both sides hold long-term ML-DSA-65 keypairs. `static_pk` is the
public key; `client_id` / VM ID is `SHA3-256(static_pk)`.

### 10.2 VM identity trust root

For a connection where the responder is a VM plugin, the initiator
(node) verifies:

```
SHA3-256(static_pk_responder) == VMID_from_signed_chain_config
```

Where `VMID_from_signed_chain_config` is loaded from a `VMRegistration`
record inside the chain's config, itself signed by the chain authority
(an ML-DSA-65 key whose hash is baked into the chain's genesis):

```
struct ChainAuthority {
  pubkey_mldsa65: [1952]      // pinned in genesis
}

struct VMRegistration {
  vm_id:          [32]         // = SHA3-256(vm_pubkey_mldsa65)
  vm_pubkey:      [1952]       // ML-DSA-65
  authority_sig:  [3309]       // chain-authority sig over (vm_id ∥ vm_pubkey)
  prev_vm_sig:    [3309]       // optional: prior VM key sig (rotation)
}
```

Rotation requires both `prev_vm_sig` (proving control of the old key)
and `authority_sig` (chain-level approval). A single key compromise
cannot replace a VM.

### 10.3 Peer-to-peer identity (non-VM)

For node-to-node ZAP, `static_pk_responder` is the peer node's
ML-DSA-65 NodeID public key. The initiator verifies
`SHA3-256(static_pk_responder)` against the expected NodeID, identical
to the existing `network/peer/scheme_gate.go` flow.

### 10.4 Ephemeral key zeroisation

After §8.2 PRK is derived:

1. Overwrite both ephemeral X25519 secret keys with zeros, then call
   `runtime.KeepAlive(secret)` so the compiler cannot elide the
   overwrite.
2. Overwrite the ML-KEM-768 ephemeral secret key likewise.
3. Set the Go slice header's length to 0 so any accidental future use
   panics rather than reads stale bytes.

A `pq_zeroize_test.go` MUST exercise this by snapshotting unsafe
pointers pre- and post-handshake and asserting the underlying memory
is zero.

## 11. Replay protection

Two independent gates:

1. **Timestamp window**: `|server_now_ns - timestamp_ns| ≤ 30 s`.
   Server uses its own monotonic clock; assumes NTP-synced peers.
2. **Nonce cache**: server keeps a 60-second-TTL Cuckoo filter of
   `(client_id, client_random)` tuples seen. Default capacity 2^20
   entries (≈4 MB memory). On hit, ALERT `0x04` and close.

If either gate trips, the handshake aborts before any state is
committed. A client whose clock is off by more than 30 s receives
ALERT `0x04` with `detail = "timestamp_out_of_window"`.

## 12. Resumption

### 12.1 Issuance

At the end of a successful full handshake, both sides derive:

```
resumption_psk = HKDF-Expand(PRK, LBL_RESUMPTION, 32)
psk_id         = SHA3-256(resumption_psk)[:16]
```

The server stores `(psk_id, resumption_psk, issued_at, client_id)`
keyed by `psk_id`, with a 3600-second TTL and a single-use flag. The
client stores `(psk_id, resumption_psk, server_endpoint)` locally.

### 12.2 Resumed handshake

Initiator sends `HELLO_PSK` (§6.8). Responder looks up `psk_id`:

- Unknown / expired / already-redeemed → ALERT `0x08`, close. The
  initiator MUST then do a full handshake.
- Valid → derive a new session:

```
x25519_shared = X25519(server_eph_sk, client_eph_pk)
H_2_psk       = §7 resumed transcript
PRK_psk       = HKDF-Extract(salt = H_2_psk,
                             IKM  = u8(len(LBL_X25519)) ∥ LBL_X25519
                                    ∥ u8(32) ∥ x25519_shared
                                    ∥ u8(32) ∥ resumption_psk)
k_i2r_psk     = HKDF-Expand(PRK_psk, LBL_SESSION_I2R, 32)
...
```

Same five expansions as §8.3. AUTH frames are NOT exchanged in
resumption — possession of `resumption_psk` is the authentication.

The server immediately marks `psk_id` as redeemed (single-use).

## 13. Rekey ratchet

Per direction, the ratchet step is:

```
epoch_n  = current epoch byte (starts at 0x00 after handshake)
k_{n+1}  = HKDF-Expand(k_n,
                       LBL_REKEY ∥ 0x00 ∥ epoch_n ∥ 0x00,
                       32)
salt_{n+1} = HKDF-Expand(k_n,
                         LBL_REKEY ∥ 0x00 ∥ epoch_n ∥ 0x01,
                         4)
epoch     = epoch_n + 1
nonce_counter = 0
```

The two HKDF expansions differ only in their last byte (0x00 vs 0x01)
so a single 36-byte expansion can produce both in one call.

Old `k_n` and `salt_n` are zeroed immediately after `k_{n+1}` is
derived.

`epoch` wraps after 256 rekeys (`0xFF → 0x00`). At wrap, the
connection MUST be closed and a fresh handshake initiated; the
implementation MUST NOT continue past epoch 0xFF. With the 1-hour
rekey ceiling, this caps a single connection at ≈ 256 hours ≈ 11 days,
which is more than any reasonable production session.

## 14. Error codes (ALERT bodies)

| Code | Name | Meaning |
|---|---|---|
| `0x00` | `none` | reserved (never sent) |
| `0x01` | `decode_error` | malformed frame, oversize length, unknown type |
| `0x02` | `unsupported_ciphersuite` | ciphersuite byte not recognised |
| `0x03` | `auth_failed` | ML-DSA signature verify failed OR AEAD tag failed |
| `0x04` | `replay_detected` | timestamp out of window OR nonce cache hit |
| `0x05` | `downgrade_refused` | peer omitted PQ scheme under StrictPQ profile |
| `0x06` | `handshake_timeout` | handshake did not complete within 5 s |
| `0x07` | `nonce_violation` | non-monotonic counter OR counter overflow without REKEY |
| `0x08` | `psk_unknown` | resumption psk_id not found, expired, or redeemed |
| `0x09` | `vm_identity_mismatch` | SHA3-256(static_pk_responder) ≠ chain-config VM ID |
| `0x0A` | `authority_sig_failed` | VMRegistration authority signature did not verify |
| `0x0B` | `policy_refused` | ChainSecurityProfile refused this connection |
| `0x0C`–`0xFF` | reserved | future use |

## 15. KAT vectors

The reference implementation MUST emit KAT vectors covering:

1. **Static handshake** — fixed ML-DSA / ML-KEM / X25519 keys, fixed
   client_random + timestamp, expected `H_0`, `H_1`, `H_2`, `PRK`,
   `k_i2r`, `k_r2i`, `salt_i2r`, `salt_r2i` to byte.
2. **DATA encrypt/decrypt** — plaintext "hello, pq", expected
   ciphertext + tag with counter = 0, 1, 2.
3. **REKEY** — derived `k_1`, `salt_1` after one ratchet.
4. **Resumption** — issued `psk_id`, resumed `PRK_psk`, derived
   `k_i2r_psk`.
5. **Replay** — server returns ALERT `0x04` for duplicate
   `(client_id, client_random)`.
6. **Downgrade** — initiator under StrictPQ sends only `{0x01}` in
   `offered_schemes`; responder advertising classical-only is rejected
   pre-AUTH with ALERT `0x05`.
7. **Tampered scheme list** — flipping one byte of `offered_schemes`
   on the wire causes AUTH verify to fail (transcript divergence) →
   ALERT `0x03`.
8. **VM identity rotation** — old VM key + new VM key + authority sig
   accepted; missing authority sig → ALERT `0x0A`.

KAT vectors live in `~/work/lux/zap/handshake/testdata/zap-pq-v1/*.json`
and are checked into the repo. Each vector is a JSON object with
hex-encoded inputs and outputs:

```json
{
  "name": "static-handshake-suite-01",
  "ciphersuite": "0x01",
  "inputs": {
    "static_sk_initiator": "...",
    "static_sk_responder": "...",
    "x25519_sk_eph_initiator": "...",
    "mlkem_sk_eph_initiator": "...",
    "x25519_sk_eph_responder": "...",
    "client_random": "...",
    "timestamp_ns": "0x...",
    "offered_schemes": "0x01"
  },
  "expected": {
    "H_0": "...",
    "H_1": "...",
    "H_2": "...",
    "PRK": "...",
    "k_i2r": "...",
    "k_r2i": "...",
    "salt_i2r": "...",
    "salt_r2i": "...",
    "auth_sig_initiator": "...",
    "auth_sig_responder": "..."
  }
}
```

The reference impl's `pq_test.go` loads every JSON in `testdata/` and
runs it through both `Initiator` and `Responder` state machines.

## 16. Go interface contract

The implementation in `~/work/lux/zap/handshake/` MUST expose:

```go
package handshake

// Identity holds a node's or VM's static ML-DSA-65 keypair.
type Identity struct {
    PublicKey  *mldsa.PublicKey   // ML-DSA-65
    PrivateKey *mldsa.PrivateKey  // sealed; never serialised raw
}

// ID returns SHA3-256(PublicKey).
func (id *Identity) ID() [32]byte

// Initiator runs the initiator side of the handshake on conn.
// On success returns a *Session keyed for AEAD framing.
type Initiator struct {
    Local       *Identity
    Expected    *Identity      // pinned responder pubkey (or nil to accept any)
    Profile     config.ProfileID
    PQMode      uint8          // 0x00 / 0x01 / 0x02 per §6.1
    Suite       uint8          // ciphersuite byte (default 0x01)
}

func (i *Initiator) Run(conn io.ReadWriter) (*Session, error)

// Responder is the server side.
type Responder struct {
    Local       *Identity
    Profile     config.ProfileID
    AcceptedSuites []uint8     // server-side ciphersuite allowlist
    ReplayCache *ReplayCache   // §11
    PSKStore    *PSKStore      // §12 (nil disables resumption)
}

func (r *Responder) Run(conn io.ReadWriter) (*Session, error)

// Session is the post-handshake AEAD-keyed stream.
type Session struct { /* opaque */ }

func (s *Session) Send(payload []byte) error
func (s *Session) Recv() ([]byte, error)
func (s *Session) Rekey() error          // explicit; automatic at thresholds
func (s *Session) Close() error
func (s *Session) PeerID() [32]byte
func (s *Session) Epoch() uint8
```

The `Session` type wraps the underlying `io.ReadWriter` with the AEAD
layer specified in §9 and the rekey ratchet in §13. `Send` increments
the local counter; `Recv` enforces monotonicity. Any error returned by
`Send` / `Recv` invalidates the session — callers MUST call `Close`
and not retry on the same session.

The KDF code lives in `handshake/kdf.go`:

```go
package handshake

// DeriveSession runs §8 on a completed transcript hash and shared
// secrets, returning the per-direction keys and salts.
func DeriveSession(
    h2           [32]byte,
    x25519Shared [32]byte,
    mlkemShared  [32]byte,
) SessionKeys

type SessionKeys struct {
    KInitToResp     [32]byte
    KRespToInit     [32]byte
    SaltInitToResp  [4]byte
    SaltRespToInit  [4]byte
    ResumptionPSK   [32]byte
}
```

The transcript builder lives in `handshake/transcript.go`:

```go
package handshake

type Transcript struct { /* SHA3-256 state */ }

func NewTranscript(suite uint8) *Transcript     // initialises with §7 prefix
func (t *Transcript) AbsorbHello(hello []byte)
func (t *Transcript) AbsorbKEM(initBytes, replyBytes []byte)
func (t *Transcript) FinishAuth(
    staticPkI, staticPkR []byte,
    offeredSchemes []uint8,
) [32]byte    // returns H_2
```

The connection wrapper lives in `~/work/lux/zap/conn_pq.go`:

```go
package zap

// WrapPQ wraps an established net.Conn with ZAP-PQ-v1 AEAD framing
// after a completed handshake. The Session it returns implements
// net.Conn for drop-in use by existing ZAP readers/writers.
func WrapPQ(conn net.Conn, sess *handshake.Session) net.Conn
```

Identity verification + chain-authority signature checks live in
`~/work/lux/zap/identity_pq.go`:

```go
package zap

// VMRegistry is loaded from the signed chain config and consulted by
// the node side of every ZAP-PQ handshake to a VM plugin.
type VMRegistry interface {
    Lookup(vmID [32]byte) (*VMRegistration, bool)
}

type VMRegistration struct {
    VMID          [32]byte
    VMPubKey      *mldsa.PublicKey
    AuthoritySig  []byte
    PrevVMSig     []byte
}

// VerifyRegistration checks AuthoritySig (and PrevVMSig if present)
// against the chain authority pubkey. Returns the verified VM pubkey.
func VerifyRegistration(
    reg *VMRegistration,
    chainAuthority *mldsa.PublicKey,
) (*mldsa.PublicKey, error)
```

The reference impl is mechanical from this point on: each section
above maps to one function or method. No design decisions remain at
the code layer.

## 17. Out of band

- **HKDF SHA3-256 implementation**: Go's `golang.org/x/crypto/hkdf`
  accepts an arbitrary `hash.Hash` constructor; pass
  `sha3.New256` from `golang.org/x/crypto/sha3`. No third-party
  dependency required.
- **ML-KEM-768 / ML-DSA-65**: use `github.com/luxfi/crypto/mlkem`
  (mode `MLKEM768`) and `github.com/luxfi/crypto/mldsa` (mode
  `MLDSA65`). Both expose `Encapsulate` / `Decapsulate` /
  `SignCtx` / `VerifySignatureCtx` matching the spec's needs.
- **X25519**: use Go stdlib `crypto/ecdh` (`ecdh.X25519()`).
- **AES-256-GCM**: Go stdlib `crypto/aes` + `crypto/cipher.NewGCM`.

No CGO required on any path.

## 18. Versioning

This document is `v1`. Any wire change — even a one-byte AAD or label
edit — MUST bump the ciphersuite byte (and the protocol label string)
and ship as a new spec document `SPEC-ZAP-PQ-v2.md` referencing
ciphersuite `0x02`. Two suites MAY coexist on the registry; the
`HELLO.ciphersuite` field selects.

Backward-incompatible changes to the framing structure itself (e.g.
new frame type IDs, new AAD fields) require a new wire identifier
`ZAP-PQ-v2` and a new magic prefix (`ZPQ2`). They cannot reuse `ZPQ1`.

## 19. Known limitations of v1; planned v2 changes

Two adversarial properties of the v1 wire format are weaker than
TLS 1.3 equivalents. Both were identified during red-team review.
Operators deploying v1 MUST account for them; both are scheduled
for amendment in `SPEC-ZAP-PQ-v2`.

### 19.1 Plaintext control frames (REKEY, ALERT)

**Limitation.** §6.6 and §6.7 carry the body of REKEY and ALERT
frames as plaintext. An on-path attacker (BGP hijacker, router with
traffic injection, malicious Wi-Fi MITM) who can write bytes onto
the TCP stream needs to send 6 bytes to terminate any active
session:

```
01 00 00 00 01     // type=ALERT, length=1
00                 // code=0x00 (any code; receiver returns the typed error)
```

The receiver decodes the injected ALERT, returns the typed error
from `Session.Recv`, and the caller closes the session. The
legitimate sender's next `Send` then fails with a closed-conn
write error. REKEY injection (7 bytes) instead desynchronises crypto
state — receiver ratchets, legitimate sender does not, the next
real DATA frame fails AEAD verify and the same termination
ALERT fires. Cost asymmetry: 6–7 bytes inbound to disconnect a
session that may be carrying GB-scale consensus traffic.

The PQ crypto holds throughout — no key compromise, no forgery —
but the connection-liveness property is downgraded from TLS 1.3
parity to TLS 1.2-era plaintext-alert weakness.

**v1 mitigation.**

- Operators MUST monitor session-termination metrics and treat
  unexplained mass disconnects as a possible on-path attack.
- Consensus participants SHOULD implement application-layer retry
  with exponential backoff; an injection costs 6 bytes but
  reconnect costs a full handshake (~2 ms ML-DSA), so the attack
  is bandwidth-symmetric only against very small payloads.
- Validators on Lux mainnet SHOULD pair this transport with route
  redundancy (multiple physical paths to peers) so a single
  network attacker cannot reach all sessions.

**v2 amendment plan.**

Move REKEY and ALERT inside the AEAD payload as a distinguished
control byte:

```
DATA plaintext = control_byte (u8) ∥ control_payload
  control_byte 0x00 = application data
  control_byte 0x01 = REKEY request
  control_byte 0x02 = ALERT
```

The outer frame stays type=DATA, sealed under the session key with
the existing AAD. An attacker without the session key cannot inject
control frames. The receiver only acts on the control byte AFTER
successful AEAD verification, matching TLS 1.3 §6 / §6.2.

Pre-handshake ALERTs (during the §4 handshake before keys exist)
stay plaintext — unavoidable. Post-handshake control is the v2 win.

This change requires `ZAP-PQ-v2` and magic prefix `ZPQ2` per §18.

### 19.2 Responder ML-DSA sign before initiator AUTH

**Limitation.** §4 / §6.4 sequence the responder to write
`KEM_REPLY` + `AUTH(R)` BEFORE reading initiator `AUTH(I)`. The
responder pays the full ML-DSA-65 signing cost (~1.5–2 ms on
commodity hardware) before the initiator has proved possession of
its long-term key. An attacker who can produce a syntactically
valid `HELLO` + `KEM_INIT` (cost ~250 µs: random X25519 +
random ML-KEM keygen + random `client_id`) gets the responder to
spend ~2 ms on a dead handshake.

CPU amplification per handshake: **~7–8×**. A single attacker
with one CPU can saturate ~7 responder CPUs. Without `ReplayCache`
in place, the attacker can REPLAY a single captured HELLO+KEM_INIT
1M times instead of generating fresh ones — amplification grows
to ~40×.

**v1 mitigation.**

- `ReplayCache` is REQUIRED under StrictPQ/FIPS profiles (enforced
  at `Responder.Run` entry; reference implementation refuses
  `nil` cache under strict mode).
- Operators MUST deploy per-source-IP rate-limit at the wrapping
  TCP listener (out of scope of this protocol). Reasonable bound
  for a Lux validator: 64 in-progress handshakes per IP per
  minute, since a single legitimate peer never needs more.
- Monitoring on `handshakes_started` minus `handshakes_completed`
  flags amplification attempts.

**v2 amendment plan.**

Two candidates under evaluation:

1. **Stateless cookie (DTLS HelloVerifyRequest style).**
   Responder issues `HelloVerifyRequest` containing
   `cookie = HMAC(server_secret, client_id ∥ src_ip ∥ floor(now/300s))`.
   Initiator MUST echo the cookie in a `HelloRetry` frame before
   the responder allocates state or signs. Cookie verification is
   ~250 ns; spoofing requires one round-trip per attempt and
   per-IP forgery. Wire changes: two new frame types
   (`HELLO_VERIFY_REQUEST = 0x09`, `HELLO_RETRY = 0x0A`); HELLO
   structure unchanged.

2. **AUTH reorder.** Responder writes `KEM_REPLY` (no sig), reads
   `AUTH(I)`, verifies, THEN writes `AUTH(R)`. Eliminates pre-AUTH
   sign cost entirely. Adds half a round-trip to handshake latency
   (~one RTT instead of zero on the initiator side). Wire changes:
   reorder §6.4 frame sequence; no new frame types.

Option 1 preserves the v1 latency profile and requires only an
attacker-cost asymmetry; option 2 trades latency for cost
elimination. The decision will land before `ZAP-PQ-v2` ships.

### 19.3 Cuckoo-vs-hash-set replay cache (implementation detail)

§11 specifies a Cuckoo filter at 2²⁰ capacity (~4 MB memory). The
v1 reference implementation uses a bounded two-generation hash-set
with the same memory order-of-magnitude (~6 MB). The functional
behaviour is identical at the spec interface; the hash-set offers
O(1) insertion under capacity-saturation where a naive single-map
implementation degraded to O(N) inline sweep. This is an
implementation choice, not a wire change — a Cuckoo-backed cache
remains spec-compliant.

### 19.4 ML-DSA randomized vs deterministic signing

§6.4 leaves the choice between FIPS 204 hedged (randomized) and
deterministic (deterministic) signing to the implementation. The
reference picks hedged by default for side-channel defence-in-depth.
KAT vectors and reproducible test fixtures use the deterministic
variant via `Identity.SignDeterministic`. Wire format is identical;
verification accepts both.
