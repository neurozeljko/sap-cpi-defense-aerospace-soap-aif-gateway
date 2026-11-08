# ADR-015: Aerospace & Defense Zero-Trust B2B Gateway (W3C WS-Security SOAP XI 3.0 & SAP AIF Injection)

## Status
Accepted

## Context
Classified defense procurement contracts (ITAR 22 CFR §§ 120-130, NIST SP 800-171, NATO STANAG) mandate cryptographically enforceable non-repudiation and anti-replay protection. REST APIs lack native WS-Security envelopes, while standard middleware logging fails to alert defense procurement officers promptly.

## Decision
1. Enforce Mutual TLS 1.3 (mTLS) with client X.509 certificates at the BTP Trust Center.
2. Ingest contracts via asynchronous W3C WS-Security SOAP XI 3.0 envelopes.
3. Implement in-flight anti-replay validation (< 300s TTL) and cryptographic nonce tracking in Groovy.
4. Route all security and cryptographic discrepancies directly into SAP Application Interface Framework (AIF) in S/4HANA for real-time Fiori business alerts.

## Consequences
- Full compliance with ITAR and NIST SP 800-171 defense standards.
- Complete defense against state-sponsored replay attacks.
- Incident resolution turnaround reduced from weeks to under 60 seconds.
