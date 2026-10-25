# Admission webhook (fleet-norm advisor/enforcer)

The admission webhook is the runtime expression of "the fleet is the
policy." It intercepts pod create/update operations on the apiserver and
compares the incoming pod against a baseline derived from your fleet's
most recent scan. When the pod deviates from what the rest of your fleet
does, it warns (advisory mode) or denies (enforce mode).

## How the baseline is derived

The baseline is a small set of fleet-wide fractions, refreshed once a
minute from the latest scan in the Fleetsweeper database:

| Fraction | What it measures |
| --- | --- |
| `DigestPinFraction` | Containers using `image@sha256:...` rather than tag references. |
| `NonRootFraction` | Containers not declared to run as UID 0. |
| `NoPrivilegeEscalationFraction` | Containers with `allowPrivilegeEscalation=false`. |

A check fires only when its fraction is at least **70%** of the fleet. Below
that threshold the fleet itself is inconsistent and the check stays silent
to avoid noisy false positives.

## Modes

- **Advisory** (default): the webhook always allows but adds warnings to
  the AdmissionResponse. The apiserver echoes those back to `kubectl` so
  the human submitting the manifest sees them.
- **Enforce**: the webhook denies admission when any check fires, returning
  a 403 with a concrete reason. Use only after you have observed the
  advisory-mode warnings for a release cycle.

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

The 70% threshold and 60s baseline cache TTL are not yet exposed as flags
in this release. Their defaults are tuned for fleets where pod-level
attributes are stable across days; if your fleet churns more aggressively,
file an issue and we will surface them.

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
