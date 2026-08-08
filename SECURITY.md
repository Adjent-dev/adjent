# Security policy

## Reporting a vulnerability in adjent

Report security issues in adjent itself through GitHub's private vulnerability reporting, using the
**Security** tab of this repository. Please do not open a public issue for a security problem.

Include the version (`adjent version`), what you observed, and the smallest set of steps that
reproduces it. We aim to acknowledge within 72 hours and to publish a fix and advisory within 90
days of confirming a report.

## Reporting a vulnerability you found in someone else's server

adjent may show you that a server belonging to another organisation is misconfigured. That
information is not ours to publish, and it is not yours either.

If you find a genuine weakness in infrastructure you do not operate:

1. Contact the maintainer or the organisation's published security address.
2. Give them 90 days to remediate before disclosing anything publicly.
3. Do not publish server names, hostnames, or anything that identifies an affected deployment while
   the issue is unfixed. An aggregate statistic harms nobody. A list of vulnerable hosts is a target
   list for whoever reads it next.

## Scope of what adjent does

adjent reads metadata that a server publishes about itself and makes one ordinary unauthenticated
request, which is the same request any MCP client makes before it holds a token. It sends no crafted
tokens, attempts no authorization bypass, and tests nothing for exploitability.

This is a deliberate limit rather than an unfinished feature. Some questions, including whether a
server enforces RFC 8707 resource indicators, cannot be answered without conducting an authorization
test. adjent reports those as out of scope instead of guessing, and it will not acquire a mode that
performs such tests against a target the operator has not authorised.

Use adjent against servers you operate, or servers you have written permission to test. Running it
broadly across infrastructure you do not own may violate computer misuse law in your jurisdiction,
including the Information Technology Act in India and the Computer Fraud and Abuse Act in the United
States.
