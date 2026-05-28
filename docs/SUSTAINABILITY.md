# Sustainability

Occasio is licensed under [Apache 2.0](../LICENSE). The core stays Apache 2.0. There is no plan to relicense the published artefact, change to a more restrictive license, or move features behind a closed source tier. The intent is that any team can install the npm package, read every line, audit the behaviour, and run it indefinitely without paying.

## How Occasio Labs makes money

Three streams, each consistent with a local-first product:

- **Compliance consulting**. Mapping Occasio chain events to specific regulatory frameworks (EU AI Act, NIST AI RMF, SOC 2 Common Criteria, sector-specific controls) and producing auditor-ready reports. The chain is produced by the open source tool; the framework mapping and the auditor-facing narrative are the consulting deliverable.
- **Curated policy bundles**. Framework-specific `policy.yml` rule sets, signed, regression-tested, and maintained against framework updates. Buyers get a bundle they can drop into `~/.occasio/policy.yml` plus a version stream of updates as the framework evolves.
- **Enterprise support contracts**. Service-level agreement on response time, security review for the published source, patch warranty on supported branches, and named technical contact. Targeted at teams that need the open source product but want a paid relationship around it.

## What Occasio Labs does not sell

- No telemetry, no aggregated usage metrics shipped to Occasio Labs, no per-call beacons.
- No data monetisation, because there is no data collection. The product cannot itself collect user data; the revenue model never has access to it.
- No managed cloud version where Occasio Labs hosts the audit chain or proxy for users.
- No per-seat fee on the open source distribution. The same npm package is available to everyone for free, indefinitely.

## Why this is consistent

The fragility in conventional open-core models is the temptation to capture value from users at the wrong layer. The pattern that fails most often is: ship an open source product whose value lives in the data it processes, then build a paid SaaS that processes the same data centrally. Users feel surveilled and trust erodes.

Occasio is structured so that pattern is unavailable. The open source product cannot collect data, because there is no Occasio cloud to send data to. The revenue model attaches to expertise and curation around the product (framework mappings, signed bundles, support contracts), not to custody of the data itself. The promise on the front of the README and the revenue streams behind the company are made of the same material.
