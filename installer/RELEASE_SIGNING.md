# Release signing credentials

The signed-release pipeline (`.github/workflows/ci.yml`, jobs
`macos-signed-artifacts` and `windows-signed-artifacts`) signs the macOS `.pkg`
and the Windows installer in CI from a fixed set of GitHub Actions
**`release-signing` Environment secrets**. This document is the
operational reference for those secrets: what each one holds, how it is encoded,
and how to rotate it before it expires — **without editing the workflow**.

## Trust boundary

- Signing runs **only on trusted events** (`push` / tag on this repository) and
  only after approval of the protected `release-signing` Environment. Missing
  credentials fail the signing job closed. Fork pull requests neither receive
  the secrets nor reach a signing job; they build **unsigned** build-health
  artifacts only.
- **Do not** convert `macos-signed-artifacts` / `windows-signed-artifacts` to
  `pull_request_target`, and do not add a `pull_request`-triggered path that can
  reach a signing step. `pull_request_target` runs with the base repo's secrets
  even for fork PRs and would break the isolation above. Forks are intentionally
  limited to unsigned artifacts.
- Every secret is materialized only as **per-run ephemeral state** (an ephemeral
  keychain on macOS, a per-run cert import on Windows, short-lived files for the
  notary key) and destroyed in an `always()` cleanup step, so a crashed job or a
  compromised runner does not persist a private key.

## Secret inventory

### macOS (Developer ID + notarization)

| Secret | Shape / encoding | Notes |
|---|---|---|
| `MACOS_DEVELOPER_ID_APP_P12_BASE64` | base64 of a `.p12` | Developer ID **Application** cert + private key. Signs the `.app` + FinderSync/File Provider appexes under the hardened runtime. |
| `MACOS_DEVELOPER_ID_APP_P12_PASSWORD` | plaintext | Import password for the Application `.p12`. |
| `MACOS_DEVELOPER_ID_INSTALLER_P12_BASE64` | base64 of a `.p12` | Developer ID **Installer** cert + private key. Signs the `.pkg` via `productsign`. |
| `MACOS_DEVELOPER_ID_INSTALLER_P12_PASSWORD` | plaintext | Import password for the Installer `.p12`. |
| `MACOS_NOTARY_KEY_P8_BASE64` | base64 of the App Store Connect API key `.p8` | Consumed by `notarytool --key`. |
| `MACOS_NOTARY_KEY_ID` | plaintext key id | The API key's Key ID (from App Store Connect → Users and Access → Integrations → Keys). |
| `MACOS_NOTARY_ISSUER_ID` | plaintext UUID | The App Store Connect issuer id. |

The identity **names** passed to `build-pkg.sh`
(`YADORILINK_APP_SIGN_IDENTITY` / `YADORILINK_PKG_SIGN_IDENTITY`) are derived at
run time from the imported keychain (`security find-identity`), so rotating a
cert does not require updating any identity-string secret.

### Windows (Authenticode)

| Secret | Shape / encoding | Notes |
|---|---|---|
| `WINDOWS_CODE_SIGN_PFX_BASE64` | base64 of a `.pfx` | Authenticode code-signing cert + private key. Imported into `Cert:\CurrentUser\My`; `signtool` selects it by thumbprint. |
| `WINDOWS_CODE_SIGN_PFX_PASSWORD` | plaintext | Import password for the `.pfx`. |

If Windows signing moves to a cloud HSM / token (Azure Trusted Signing, DigiCert
KeyLocker, etc.), the abstraction point is the Inno Setup **SignTool command**
built in the `Build Windows installer (signed)` step and passed to
`build-installer.ps1 -SignToolCommand`. Swap that command (and the secret(s) it
needs) for the provider's `signtool` invocation; the `.iss` and the rest of the
workflow are provider-agnostic.

## Encoding a certificate for a secret

macOS `.p12` / notary `.p8` / Windows `.pfx` are all stored base64-encoded:

```sh
# macOS / notary / Windows — same idea for each file:
base64 -i DeveloperID_Application.p12 | pbcopy      # then paste into the secret
base64 -i AuthKey_XXXXXXXXXX.p8       | pbcopy
base64 -i codesign.pfx                | pbcopy
```

On Linux use `base64 -w0 file`. The workflow decodes with `base64 --decode`
(macOS) / `[Convert]::FromBase64String` (Windows), so a single-line or wrapped
value both work.

## Issue / expiry tracking

Record, out of band (e.g. a private ops note or calendar reminders), for each
credential: **issued date, expiry date, and the secret name it backs.**

- Developer ID Application / Installer certificates: typically ~5 years.
- App Store Connect API key: no hard expiry, but revoke + reissue on personnel
  changes.
- Windows code-signing cert: 1–3 years depending on CA.

The verification gate fails a release **loudly** (red run) if a signature or
notarization is invalid, so an expired cert surfaces as a failed release, never
a silent downgrade to unsigned. Set expiry reminders ~30 days ahead so rotation
happens before that failure.

## Rotation procedure (no workflow edit)

1. **Regenerate** the credential:
   - macOS: create a new Developer ID Application/Installer cert in the Apple
     Developer portal (or a new App Store Connect API key), export the cert +
     key as a `.p12` with a fresh import password.
   - Windows: obtain a renewed `.pfx` from the CA (or reconfigure the cloud-HSM
     signing profile).
2. **Re-encode** to base64 (see above).
3. **Update the `release-signing` Environment secret** with the new value:
   ```sh
   gh secret set --env release-signing MACOS_DEVELOPER_ID_APP_P12_BASE64 < app_p12.b64
   gh secret set --env release-signing MACOS_DEVELOPER_ID_APP_P12_PASSWORD --body '<new-password>'
   # ...and the corresponding *_PASSWORD / key-id / issuer secrets as needed.
   ```
4. Re-run the release (or push) and confirm the in-CI verification gate passes
   (`pkgutil --check-signature` + `spctl` on macOS; `signtool verify /pa /all`
   on Windows).

No change to `ci.yml`, `build-pkg.sh`, or `yadorilink.iss` is required to rotate
— only the secret values change.
