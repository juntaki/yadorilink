# Public Beta Release Gate

The data-loss release criteria are defined by
[`design/data-durability-model.md`](design/data-durability-model.md). A release
candidate must keep every referenced DL-1 through DL-7 regression test green;
CI verifies that the named tests still exist.

Every public beta candidate must have an evidence record for each gate item.
Release-blocking items must pass before the build is published.

Blocker classes:
- `blocker`: release must not proceed while failing.
- `conditional`: release can proceed only with documented scope, impact, owner,
  and user-facing workaround.
- `non-blocking`: accepted limitation for beta release notes.

Required evidence fields:
- build identifier;
- platform/version/architecture;
- matrix cell from `docs/COMPATIBILITY.md`;
- owner;
- pass/fail status;
- blocker class;
- evidence location;
- date;
- notes and known limitations.

## Gate Checklist

| Area | Required Check | Blocker |
|---|---|---|
| Compatibility | Supported runtime target cells in `docs/COMPATIBILITY.md` have evidence | blocker |
| Install | Fresh install succeeds on supported macOS and Windows beta targets | blocker |
| First run | Account/device setup and first link complete with preflight warnings | blocker |
| Sync smoke | Two-device create, modify, rename, delete, and conflict smoke pass | blocker |
| Daemon lifecycle | daemon start, stop, pause, resume, restart, and post-login restart pass | blocker |
| OS restart | Linked folders recover after OS restart | blocker |
| Uninstall | Uninstall removes binaries/services/extensions and documents retained data | blocker |
| Updates | Automatic/manual update path works or is documented as unavailable | conditional |
| Diagnostics | Redacted diagnostics bundle/export works on supported platforms | blocker |
| Signing | macOS artifacts are signed/notarized; Windows artifacts are Authenticode-signed or checksum-documented for internal testing only | blocker |
| Security | Threat-model/security-review release blockers are closed or waived with rationale | blocker |
| Known limitations | User-facing release notes list every accepted non-blocking limitation | blocker |

Pre-release development-build upgrades are intentionally not a gate. Until the
first public compatibility baseline is declared, development state may be reset
and components are expected to use the same current protocol generation. After
the first public release, supported upgrade evidence becomes release-blocking.

## Evidence Template

Before publishing a candidate, collect these fields in a JSON file and run:

```bash
python3 scripts/check-beta-release-gate.py --candidate path/to/beta-candidate.json
```

The file uses schema `yadorilink-beta-candidate/1`, with top-level `build_id`
and `records`. Each record carries the fields below plus separate `platform`,
`version`, `architecture`, and `gate` values copied exactly from the
compatibility matrix and Gate Checklist. The validator requires one passing
record for every supported compatibility cell and every gate. Only a
`conditional` gate may use `status: "waived"`, and it still requires an owner,
evidence location, and rationale in `notes`.

Slow load/soak evidence comes from the `Beta heat tests` workflow
(`.github/workflows/beta-heat.yml`). It runs weekly and on demand without
adding hours to normal pull-request CI. Record the successful Actions run URL
in the candidate's Sync smoke or Daemon lifecycle evidence as applicable.

```markdown
## Beta Evidence: <build-id>

- Date:
- Owner:
- Platform/version/architecture:
- Compatibility matrix cell:
- Gate area:
- Check:
- Status: pass | fail | not-run
- Blocker class: blocker | conditional | non-blocking
- Evidence location:
- Notes:
- Known limitation entry required: yes | no
```

## Known Limitations Template

```markdown
### <limitation title>

- Scope:
- Impact:
- Workaround:
- Affected compatibility cells:
- Owner:
- Revisit trigger:
```

## Security Release Blockers

These are `blocker`-class items under the **Security** gate row above
(`docs/THREAT_MODEL.md`'s threat-model/security-review release blockers) —
each must be closed or explicitly waived with documented rationale before any
beta build is published to real users, not merely tracked as a known
limitation.

### Update signing ceremony and production key are not yet evidenced

Developer builds pin the known `yadorilink-beta-dev-2026` key. Release builds
instead require a key id and public key at compile time and cannot silently
fall back to that development key. This closes the packaging path, but automatic
or manually triggered update MUST NOT be enabled for real users until the
production ceremony in `docs/UPDATE_SIGNING.md` has been performed and all of
the following have recorded evidence:

- the private key matching the pinned public key exists only as the
  `release-signing` GitHub Environment Secret, protected by required reviewers,
  and is not duplicated as a repository/organization secret;
- signing runs only after `release-signing` environment approval for a nightly
  build, an immutable beta tag, or a manual update-control operation, never for
  pull requests or ordinary build-health CI;
- the documented signing ceremony was followed, including independent review;
- the documented key-rotation and revocation procedures have named owners;
- release artifacts are reproducible and accompanied by an SBOM;
- manifest-signing authority is kept organizationally and technically
  separate from platform code-signing authority (macOS Developer ID /
  Windows Authenticode signing) — compromise of one must not automatically
  compromise the other.

Evidence for this item must record which of the above are satisfied, by
whom, and where the supporting evidence lives, using the Evidence Template
below.

## Current Dry-Run Gaps

The current repository has the gate definition and compatibility matrix, but a
beta candidate is not approved until these evidence records exist:

- fresh signed/notarized macOS install evidence;
- fresh signed Windows install evidence;
- two-device sync smoke on supported macOS and Windows cells;
- uninstall evidence;
- diagnostics export evidence;
- known limitations release notes.
