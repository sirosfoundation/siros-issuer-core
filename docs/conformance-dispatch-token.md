# CONFORMANCE_DISPATCH_TOKEN — creation and setup

The issuer repo's conformance workflow
(`.github/workflows/conformance.yml`) publishes release-tag conformance
reports to **conformance.siros.org** by dispatching the conformance repo's
own publish workflow (`repository_dispatch`, event `conformance-issuer`).
The dispatch needs a token — this one.

## What it is

A **GitHub fine-grained personal access token (PAT)** with exactly one
permission: **Actions: write** (the repository-dispatch right) on
**`sirosfoundation/siros-conformance`** — nothing else. It cannot read
code, cannot merge, cannot touch anything outside that one repo's dispatch
endpoint. (A classic PAT with the full `repo` scope would also work but
grants far more than the job needs; the fine-grained form is the least
privilege.)

## Creating it

1. Sign in to GitHub as yourself (or the service account the org uses for
   automation), then:

   **Settings → Developer settings → Personal access tokens → Fine-grained
   tokens → Generate new token**

2. Fill in:

   | Field | Value |
   |---|---|
   | **Token name** | `conformance-dispatch` |
   | **Expiration** | 90 days (GitHub's cap for fine-grained tokens; set a calendar reminder to rotate — the workflow will start failing with 401/403 when it expires, which is the rotation signal) |
   | **Resource owner** | `sirosfoundation` |
   | **Repository access** | **Only select repositories** → `sirosfoundation/siros-conformance` |
   | **Permissions → Repository permissions → Actions** | **Read and write** |

   Leave every other permission **No access**. The token preview should
   show exactly one line: "Actions (read and write) — 1 repository".

3. **Generate token** — copy the value immediately (`github_pat_…`). It is
   shown once.

## Setting it in this repo

**`sirosfoundation/siros-issuer-core` → Settings → Secrets and variables →
Actions → New repository secret**:

| Field | Value |
|---|---|
| **Name** | `CONFORMANCE_DISPATCH_TOKEN` |
| **Secret** | *(the pasted token value)* |

No environment needed — plain repository secret, so the `conformance.yml`
workflow (no environment declared) reads it directly.

> The same token serves `siros-wallet-core`'s conformance workflow (event
> `conformance-wallet`) — one token, both dispatches, when the org
> rotates it both repos rotate together.

## Verifying it

Once set, trigger a release-tag conformance run (or wait for the next
release push):

```
gh run list -R sirosfoundation/siros-issuer-core --workflow conformance.yml
```