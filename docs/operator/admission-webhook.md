# Admission webhook (fleet-norm advisor/enforcer)

The admission webhook is the runtime expression of "the fleet is the
policy." It intercepts pod create/update operations on the apiserver and
compares the incoming pod against a baseline derived from your fleet's
most recent scan. When the pod deviates from what the rest of your fleet
does, it warns (advisory mode) or denies (enforce mode).

## How the baseline is derived

The baseline is a small set of fleet-wide fractions, refreshed once a
minute from the latest scan in the Fleetsweeper database:

| Fraction&nbsp;                     | What it measures                                            |
|------------------------------------|-------------------------------------------------------------|
| `digest_pin_fraction`              | Containers using `image@sha256:...` rather than a tag.      |
| `non_root_fraction`                | Containers not declared to run as UID 0.                    |
| `no_privilege_escalation_fraction` | Containers with `allowPrivilegeEscalation=false`.           |
| `named_service_account_fraction`   | Pods running under a ServiceAccount other than `default`.   |
| `read_only_root_fs_fraction`       | Containers with `readOnlyRootFilesystem=true`.              |

Each cluster contributes its own counts, and a scanner that did not
complete on a cluster contributes nothing, so a blind cluster cannot
drag the norm. A check fires only when its fraction is at least **70%**.
Below that the fleet itself is inconsistent and the check stays silent.

To freeze the norm instead of following the latest scan, pin it to a
file. See [Pinning and auditing the admission baseline](baseline.md).

## Modes

- **Advisory** (default): the webhook always allows but adds warnings to
  the AdmissionResponse. The apiserver echoes those back to `kubectl` so
  the human submitting the manifest sees them.
- **Enforce**: the webhook denies admission when a check fires on a norm
  that has held for the stability window (below), returning a 403 with a
  concrete reason. Use only after you have observed the advisory-mode
  warnings for a release cycle.

Any mode value other than `enforce` behaves as advisory, and a malformed or
missing AdmissionReview is allowed with a warning in every mode, enforce
included.

## Stability gate

A norm that appeared in one scan is not yet a norm. In enforce mode a
check denies only when its fraction has been at or above 70% in each of
the last N consecutive scans, where N is `--admission-stable-scans`
(default 3, Helm value `admission.stableScans`). Until then the pod is
allowed, and the response carries the check's usual warning plus one
that names the check and how far along it is:

```
fleetsweeper: digest-pin not enforced: its fleet norm has held for 1 of the 3 consecutive scans enforcement needs
```

The run is broken by any scan whose fraction was below the threshold or
whose sample was too small to evaluate. A fresh install therefore
enforces nothing until N scans have landed, and a norm that flickers
around 70% never enforces at all. Each baseline refresh reads the last N
scans from the store, once a minute. A pinned baseline is exempt: it is
a norm an operator chose, and it does not move between scans.

## Rollout: warn first, enforce on purpose

Enforcement is designed as the last step of a deliberate workflow, not
the first:

1. **Run in advisory mode.** This is the default. Every check runs and
   every warning is emitted; nothing is denied.
2. **Read the warnings.** They are a complete preview of what enforce
   mode would have denied, pod by pod, before enforcement has teeth.
3. **Decide the norm is a rule you actually want.** A fleet norm is an
   observation ("most of your fleet pins image digests"), not
   automatically a rule. Promote it only when you agree it should be one.
   If it should be a rule regardless of what the fleet does, write it in
   Kyverno or Gatekeeper instead.
4. **Opt into enforce mode.** Only then do denials start.

The handler is defensive in every mode, so the workflow above is safe to
run on a production apiserver from day one:

- It defaults to allow and only ever denies under enforce mode.
- It refuses to evaluate at all until the baseline clears the minimum
  sample (30 containers across 10 pods), so a statistical claim needs a
  sample before it gets teeth.
- It denies only on a norm that has held for the stability window.
- A pod it cannot decode is allowed with a warning, never denied.
- Warnings are emitted in every mode, so operators see what enforcement
  would do long before enabling it.

## Enable

```yaml
admission:
  enabled: true
  mode: advisory          # or "enforce"
  failurePolicy: Ignore   # safer default; Fail blocks all admission if
                          # the webhook is down.
  caBundle: ""            # leave empty when using cert-manager.
```

Combine with cert-manager for production:

```yaml
admission:
  enabled: true
  webhookAnnotations:
    cert-manager.io/inject-ca-from: fleetsweeper/fleetsweeper-admission-cert
```

Or run with the generated certificate and inject the CA bundle by other
means (kubectl patch, custom Job, etc.). Fleetsweeper issues the serving
cert from an internal CA and rotates it automatically before expiry; the
CA bundle stays valid for ten years, so it is patched once. File-backed
certificates (`--admission-cert` / `--admission-key`) are reloaded from
disk when the files change, so cert-manager secret rotation needs no
restart.

## What it does not do

- It does not mutate pods. The webhook is validating only; suggested
  remediations come through `fleetsweeper remediate` PRs.
- It does not block pods on a freshly-installed Fleetsweeper. When the
  baseline has fewer than 30 containers / 10 pods of data, the webhook
  short-circuits to allow.
- It does not replace OPA Gatekeeper or Kyverno. Rule-based policy and
  norm-based detection are complementary. Run both.

## Tuning

| Flag&nbsp;                 | Default  | Effect                                                    |
|----------------------------|----------|-----------------------------------------------------------|
| `--admission-mode`         | advisory | `enforce` turns on denials.                               |
| `--admission-stable-scans` | 3        | Consecutive scans a norm must hold before enforce denies. |
| `--admission-baseline`     | empty    | Pinned baseline file used instead of the latest scans.    |

The 70% threshold and the 60s baseline refresh are fixed in this
release.

## Verifying

After enabling, submit a pod that diverges from the norm:

```yaml
apiVersion: v1
kind: Pod
metadata: { name: digest-test, namespace: default }
spec:
  containers:
    - name: nginx
      image: nginx:1.27  # tag, not digest
```

The response should carry one or more `fleetsweeper:` warnings explaining
which check fired. In enforce mode, the create returns a 403 instead.
