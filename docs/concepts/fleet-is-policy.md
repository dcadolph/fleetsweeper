# The fleet is the policy

Most Kubernetes posture tools start from a written rulebook: a YAML of
checks, or a community ruleset like CIS or NSA hardening. They run that
rulebook against each cluster and report violations. This works well when
you know what you want — but it leaves a gap.

The gap is *the rule you never wrote*.

If 19 of your 20 clusters use `restricted` Pod Security Admission and one
uses `baseline`, no off-the-shelf rulebook will flag that. Most rulebooks
would happily pass `baseline` (it is a valid choice). The drift only
matters because the rest of your fleet decided otherwise.

Fleetsweeper inverts the question. Instead of "does this cluster violate
the rulebook?", it asks "does this cluster diverge from the rest of your
fleet?". The baseline is *your fleet's median behaviour*. The findings are
the outliers.

## Why this works at scale

- **No upfront authoring.** You can deploy fleetsweeper against 50 clusters
  and see useful findings on day one. You do not need to know which checks
  matter; the data tells you which ones are surprising.
- **Resilient to environment drift.** As your fleet evolves, the baseline
  evolves with it. There is no rulebook to keep current.
- **Complements rule-based tools.** Polaris, Kubescape, kube-bench, and
  Gatekeeper all stay valuable. Fleetsweeper finds what they cannot.

## What it cannot do

- **Flag the right behaviour when the whole fleet is wrong.** If every
  cluster uses `:latest` tags, no clusters are outliers — and no findings
  fire. For that you still want a rulebook.
- **Compare a single cluster to itself.** With only one cluster there is no
  fleet baseline; only trends across time are available.

## How it computes the baseline

For metrics like "number of CRDs", "fraction of pods using digest pins",
or "PSA mode", fleetsweeper computes the fleet median and the median
absolute deviation (MAD). Clusters more than `threshold * MAD` from the
median are flagged as outliers. The default threshold is 3.5, which
corresponds roughly to a 99.7% confidence band under a normal-ish
distribution. The threshold is configurable per request.

For categorical metrics (PSA mode, ingress class, CSI driver), fleetsweeper
computes the mode and flags clusters that disagree with the plurality.

For trends across time it fits an ordinary least squares line through the
recent score history and only surfaces a "regressing" or "improving"
verdict when the t-statistic exceeds 2.0 — so a noisy two-scan window does
not produce false alarms.
