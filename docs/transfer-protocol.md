# pa transfer protocol

`pa-xfer` transfers password entries between stores that intentionally use
different age identities. It never copies an identity and never makes one
machine a recipient of another machine's at-rest ciphertext.

## Invariants

- Transfer is set union by entry name.
- An existing destination name is always preserved without comparing values.
- There is no overwrite, force, newest-wins, or conflict-resolution mode.
- Secret values never enter argv, environment variables, logs, or plaintext
  files.
- Only an age-encrypted bundle may be stored or cross an SSH process boundary.
- Imported values are re-encrypted to the destination's local recipients before
  publication.
- Each published entry is complete, locally decryptable ciphertext installed
  with an atomic no-replace operation.
- A batch may apply a valid prefix before interruption. Rerunning is safe and
  converges monotonically.

## PAXFER1 framing

The plaintext inside an age envelope is a binary stream. Integers are unsigned
big-endian values.

```text
magic             8 bytes: "PAXFER1\n"

entry-start       0x01
name-length       uint32
name              name-length bytes of UTF-8

entry-data        0x02
chunk-length      uint32
chunk             chunk-length arbitrary bytes

entry-end         0x03
value-length      uint64
value-sha256      32 bytes

bundle-end        0xff
entry-count       uint32
transcript-sha256 32 bytes
EOF
```

Every entry has exactly one `entry-start`, zero or more `entry-data` frames, and
one `entry-end`. The value digest covers the concatenated data bytes. The
transcript digest covers every byte from `magic` through the bundle-end entry
count, excluding only the transcript digest itself.

The age envelope supplies confidentiality and authentication. The inner hashes
detect implementation and re-encryption errors; they are never printed or
stored outside the encrypted bundle and destination transaction metadata.

Decoders reject unknown frames, malformed lengths, duplicate names, trailing
bytes, truncated streams, mismatched sizes or digests, missing bundle ends, and
resource-limit violations.

## Names

Names are UTF-8 relative slash-separated paths. Components must be non-empty and
cannot be `.`, `..`, `.git`, or begin with `.pa-`. Absolute paths and control
characters are rejected. Names are never silently normalized.

Destination publication remains the final authority for case-insensitive or
filesystem-specific collisions: no-replace publication treats a collision as
an existing destination and preserves it.

## SSH shape

The only remote shell command is fixed:

```text
pa-xfer serve
```

Names, paths, recipients, and options travel inside the versioned protocol, not
as interpolated shell fragments. SSH host-key verification authenticates the
machine. The peer's public age-recipient fingerprint is pinned separately to
detect accidental identity or store changes before local secrets are decrypted.

The SSH transport begins with `PAXSSH1\n` and one command byte. Each SSH
connection handles exactly one bounded request:

- `recipient` returns the public recipient file used to calculate its SHA-256
  fingerprint.
- `push` carries a length-delimited PAXFER1 age envelope and imports it on the
  remote store.
- `pull` carries the caller's public recipient file and returns a
  length-delimited PAXFER1 age envelope encrypted to it.

The recipient file is public. Secret values only occur inside the PAXFER1
envelope, which is itself always inside an age envelope. Neither plaintext
entries nor age identities cross the SSH process boundary.

Bidirectional sync is two explicit one-way operations: push, then pull. It is
not represented as an atomic distributed transaction. If push succeeds and
pull fails, rerunning is safe because imports are monotonic and never replace an
existing name.

## Saved peer trust

`pa-xfer sync PEER` resolves a versioned trust record from
`$PA_DIR/peers/PEER.json`. A record contains only its canonical peer name, SSH
destination, and the SHA-256 fingerprint of the exact raw remote recipient
file. It does not contain recipient bytes, SSH executable paths, SSH options,
remote commands, or secret data. Persistent connection settings belong in
OpenSSH configuration.

The registry is local to one pa store and is deliberately excluded from the
password Git repository, transfer bundles, snapshots, and restore. Password
rollback must not roll back a recipient trust decision.

Peer directories must be real mode-0700 directories. Records must be regular,
non-symlink mode-0600 files with canonical lowercase names and fingerprints.
Parsing rejects duplicate or unknown JSON fields, unknown versions, trailing
data, name/filename disagreement, oversized records, and unsafe SSH hosts.

Add uses atomic no-replace publication. Replace and remove compare the current
record with the version the operator inspected before mutating it under the
store lock. Replace is the only operation allowed to overwrite active peer
trust. Sync never changes the registry.

Named sync loads the record, fetches and fingerprints the live recipient, then
acquires the store lock and re-reads the record before export. It holds that
trust lease through delivery of the encrypted push bundle. A recipient mismatch
or an earlier local record change aborts before local password entries are
decrypted; replace and remove cannot complete while a verified push is in
flight. Pairing and explicit replacement may prompt; sync never does.

The low-level `sync --host HOST --peer-fingerprint SHA256` path bypasses the
registry and remains available for recovery from a corrupt or unavailable peer
registry.

## Recovery boundary

Import snapshots contain the complete encrypted password tree and Git metadata
before and after a changing transaction. `receipt.json` records counts, paths,
timestamps, and transaction state, never secret values or plaintext hashes.

`pa-xfer restore` is deliberately separate from import and sync. It is the only
command permitted to replace an existing entry or remove an entry that is not
in the selected snapshot, and requires `--yes`. It verifies that every selected
ciphertext decrypts with the current machine identity before mutation. Changes
are entry-atomic and journaled; the current store is snapshotted again before
restore. The selected snapshot's Git database remains evidence while the live
repository records restoration as a new commit.
