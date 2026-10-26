# The fleet is the policy

Most Kubernetes posture tools start from a written rulebook: a YAML of
checks, or a community ruleset like CIS or NSA hardening. They run that
rulebook against each cluster and report violations. This works well when
you know what you want. But it leaves a gap.

The gap is *the rule you never wrote*.

If 19 of your 20 clusters use `restricted` Pod Security Admission and one
uses `baseline`, no off-the-shelf rulebook will flag that. Most rulebooks
would happily pass `baseline` (it is a valid choice). The drift only
matters because the rest of your fleet decided otherwise.

Fleetsweeper inverts the question. Instead of "does this cluster violate
the rulebook?", it asks "does this cluster diverge from the rest of your
fleet?". The baseline is *your fleet's median behavior*. The findings are
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

- **Flag the right behavior when the whole fleet is wrong.** If every
  cluster uses `:latest` tags, no clusters are outliers. And no findings
  fire. For that you still want a rulebook.
- **Compare a single cluster to itself.** With only one cluster there is no
  fleet baseline; only trends across time are available.

## How it computes the baseline

For numeric fields like "number of CRDs" or "namespaces without a network
policy", fleetsweeper computes the median and the median absolute deviation
(MAD) over the clusters that report the field, and flags a cluster when its
modified z-score is over the threshold:

```
|0.6745 * (x - median) / MAD| > 3.5
```

The threshold is configurable per request. For string fields (PSA mode,
ingress class, Kubernetes version) the norm is the most common value, and a
field is a norm only when that value holds at least 60% of the clusters. For
list fields (CRDs, services) the norm is the set of members at least 60% of
clusters have.

These detectors need a population of 8 or more. A population of 3 to 7 runs a
leave-one-out majority diff that flags one cluster only when every other
cluster agrees, and its results carry `limited_sample`. One or two clusters
get no outliers, and the report says why. [Outliers](outliers.md) has the
details, and [Distributions](distributions.md) shows how the band is drawn.

For trends across time it fits a least squares line through recent scans and
calls a metric worsening or improving only with at least 5 scans, an R² of
0.25 or more, a slope t-statistic of 2 or more, and a slope of at least 5%
per scan, so a noisy window does not raise false alarms.

## Cohorts: the fleet is several populations

A fleet is rarely one population. Production clusters are larger than edge
clusters, and that is a design, not drift. Tag clusters with a `cohort` tag
and each cohort gets its own norm. A cluster in a tagged cohort answers to
that cohort's norm:

- A fleet outlier whose value sits inside its cohort's norm is held by the
  cohort. It stays visible on the fleet strip as a hollow dot, marked "held
  by their cohort", and raises no finding.
- A cluster outside its cohort's norm is flagged against the cohort, whether
  or not the fleet would flag it.
- Deviation mass, the measure the dashboard ranks clusters by, takes a tagged
  cluster's z from its cohort.

Untagged clusters are grouped automatically, and auto cohorts do not hold
fleet outliers: only a cohort an operator declared does.

Location is identity, not configuration. The geo scanner's fields are neither
divergences nor norms.

## What if a cluster matched the norm

Any finding the norm raised has a What if button in the dashboard, backed by
`POST /api/whatif`. It rebuilds the report with that cluster's value set to
the norm (the median, the most common value, or the consensus members, or
with the cluster removed) and returns the score before and after, how the
median and MAD move, the field's distribution before and after, and which
clusters would clear or newly flag. Moving one cluster moves the norm, so a
fix can expose a neighbor the old band hid. Nothing is written: the
projection reads the stored scan. With no scope given, the fix aims at the
cluster's tagged cohort when it has one, and the fleet otherwise.
