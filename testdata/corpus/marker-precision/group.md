# marker-precision

**Models:** The inverse false-positive risk from [[credential-marker-gap]]
and [[credential-read-gap]] — instead of "should have matched and
didn't," this group asks "does it match things it shouldn't?" A package
legitimately reading configuration that happens to live in the same
directory family as a real secret marker.

**Rule NOT triggered:** neither fixture in this group produces a
`Credential file read` finding — both open paths deliberately adjacent
to, but distinct from, an actual marker.

**Fixtures:**
- `known-hosts.go` — opens `$HOME/.ssh/known_hosts`, a real SSH-client
  file that lives next to `id_rsa`/`id_ed25519`/etc. but holds only host
  public keys and fingerprints, not private key material. Proves the
  rule's `.ssh/` markers are specific filenames, not the whole directory.
- `generic-config.go` — opens a made-up file under `$HOME/.config/`, not
  `.config/gcloud/credentials.db` (the one path under `.config/` the
  rule actually matches). Proves the marker is that one file, not
  "anything under `.config/`".

**Why this matters:** `credentialPathMarkers` in `report.go` is a flat
list of substrings, matched with `strings.Contains` — a marker that was
too broad (say, matching on `.ssh/` alone rather than each key filename)
would flag `known_hosts`, `authorized_keys`, and `config` right alongside
actual private keys, which is exactly the kind of over-broad rule
INTENT.md §2's signal-to-noise requirement rules out. This group is the
regression check for that failure mode, the same way `native-build-style`
is the regression check for over-flagging on volume/subprocess activity.
