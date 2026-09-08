# APT repository

Builds and serves a real APT repository for the `.deb` `installer/linux/build-deb.sh`
already produces: signed `Release`/`InRelease` metadata, `Packages`
indices, and a `pool/` of `.deb` files, hosted on the same Cloudflare
Worker + R2 infrastructure `coordination-worker` already runs for the
update manifest (`src/routes/apt.ts`, bucket `yadorilink-apt`).

## Install

```sh
curl -fsSL https://yadorilink.juntaki.com/apt/install.sh | sudo sh
sudo apt update
sudo apt install yadorilink
```

Or, if you'd rather install a `.deb` than pipe a script to a shell:

```sh
curl -fsSLO https://yadorilink.juntaki.com/apt/yadorilink-archive-keyring_1_all.deb
sudo dpkg -i yadorilink-archive-keyring_1_all.deb
sudo apt update
sudo apt install yadorilink
```

Both paths do exactly the same two things -- install the archive's public
signing key and register a `deb822` sources entry -- and nothing more.
Neither one calls `apt-get update`/`apt-get install` on your behalf; see
`install.sh`'s own header comment for why that boundary is deliberate.

Requires **apt >= 2.4** (Debian 12 "bookworm" / Ubuntu 22.04 "jammy" or
newer) for the `deb822` `.sources` format. On an older system, use the
one-line legacy format instead:

```sh
curl -fsSL https://yadorilink.juntaki.com/apt/yadorilink-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/yadorilink-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/yadorilink-archive-keyring.gpg] https://yadorilink.juntaki.com/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/yadorilink.list
sudo apt update
sudo apt install yadorilink
```

## What's here

- `install.sh` — the `curl | sudo sh` registration script.
- `build-keyring-deb.sh` — builds `yadorilink-archive-keyring_<version>_all.deb`
  (installs the same signing key + a `.sources` file, for a `dpkg -i`
  install instead of piping a script to a shell).
- `README.md` — this file.

`scripts/ci/build-apt-repo.sh` (not under this directory, alongside this
project's other CI-only release scripts) assembles the actual repository
tree (`dists/`, `pool/`) from a set of already-built `.deb` files and
signs it. See that script's own header comment for the exact layout it
produces.

## Signing key custody

**The production APT signing key was not generated as part of this
change.** That is deliberate, not an oversight: `docs/UPDATE_SIGNING.md`
documents this project's one existing precedent for a comparable decision
(the Ed25519 update-manifest signing key), and its Key Ceremony section is
explicit that generation requires *"a trusted machine with full-disk
encryption"* and recorded *"participants, date, device, and key
identifier"* -- a real ceremony with a human present, not something to
fold into an automated packaging change. Generating the production APT
key is a maintainer action; this repository only ever consumes its public
half (`installer/linux/apt/build-keyring-deb.sh`,
`scripts/ci/build-apt-repo.sh`).

**What exists today, for real, verified in this environment:**

- `scripts/ci/build-apt-repo.sh` end-to-end, including the GPG
  signing/verification step, tested against a **clearly-labeled
  development-only** key generated in an ephemeral `GNUPGHOME` (never
  committed, never used outside this local test) purely to prove the
  mechanism works: `gpg --verify` accepted both the resulting `InRelease`
  and `Release.gpg`, and a real `apt-get update && apt-get install
  yadorilink` against the resulting repo succeeded in a clean Ubuntu 24.04
  container.
- `oss-public/.github/workflows/release.yml`'s "Build and publish the APT
  repository" step, gated exactly like the existing manifest-signing step:
  it requires `APT_SIGNING_KEY` as a `release-signing` Environment secret
  and fails **closed** (skips publishing, does not error the release) when
  it's absent -- see that workflow. As of this writing that secret does
  not exist (verified via `gh api repos/juntaki/yadorilink/environments/release-signing/secrets`),
  so this path has never run for real and cannot yet produce a real signed
  repository.

**What a maintainer needs to decide and do**, mirroring
`docs/UPDATE_SIGNING.md`'s ceremony as closely as this signing scheme
allows (GPG rather than raw Ed25519, but the same trust boundary):

1. On a trusted machine, generate a **dedicated** GPG key for this purpose
   only (do not reuse a personal/other-project key): an Ed25519 (`ed25519`
   for signing) key is consistent with this project's existing Ed25519
   manifest key and is supported by apt >= 1.4 (see the compatibility note
   below), or RSA-4096 if broader legacy-apt compatibility is ever needed.
   Record participants, date, device, and key fingerprint as release
   evidence, same as the manifest-key ceremony.
2. Export the private key (`gpg --export-secret-keys --armor <key-id>`)
   and store it **only** as the `APT_SIGNING_KEY` secret in the public
   repository's protected `release-signing` Environment -- never as a
   repository- or organization-level secret, matching
   `MANIFEST_SIGNING_KEY`'s existing rule.
3. No separate public-key repository variable is needed (unlike the raw
   Ed25519 manifest key): `build-apt-repo.sh`'s signing step derives the
   key id from the imported secret key itself, and the release workflow
   exports + publishes the public half (`yadorilink-archive-keyring.asc`)
   automatically as part of the same step.
4. Rotation/revocation should follow `docs/UPDATE_SIGNING.md`'s same
   additive, overlapping procedure: publish the new key's `.asc` and
   keyring `.deb` alongside the old one for a transition window (apt has
   no equivalent of the client's own trust-root compile-time pinning, so
   the overlap only needs to last as long as it takes existing installs to
   re-run `install.sh`/update the keyring package) before retiring the old
   key.

### apt/GPG algorithm compatibility

Modern `apt` (>= 1.4, i.e. any currently-supported Debian/Ubuntu release)
and `gpg` (>= 2.4, used throughout this repo's tooling) both support
Ed25519 `Release` signatures without issue -- verified directly in this
track's own testing (the dev key above is Ed25519, and both `gpg --verify`
and the real `apt-get update` container test accepted it cleanly). RSA
remains the more universally-compatible choice for an archive that also
needs to support genuinely ancient apt versions; this project's minimum
supported target (Ubuntu 22.04 / Debian 12, per the `.sources` format
requirement above) does not need that.
