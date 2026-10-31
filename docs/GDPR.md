# Data protection notes for the Layer 1 collectors

This describes what the code does to support GDPR compliance and what an organisation deploying it must still do. It is engineering documentation, not legal advice. Have your data protection officer or legal adviser confirm the lawful basis and local employment rules before any deployment on real people's devices.

## What the code does

| GDPR principle | Measure in the code |
|---|---|
| Data minimisation (Art. 5(1)(c)) | Events carry only collector, host, class ids, action, optional pseudonymised agent id and tool name. Matched text is never stored or returned (`Matcher` returns counts; `Layer1Event` rejects unknown fields). Destinations are reduced to a host, so URL paths and query strings never reach an event. Clean traffic produces no event. |
| Purpose limitation (Art. 5(1)(b)) | The proxy inspects only hosts in the policy's `ai_hosts`; other hosts are passed through and their bodies are never read. Only POST, PUT and PATCH bodies are scanned. |
| Storage limitation (Art. 5(1)(e)) | The local buffer deletes events after delivery, after 7 days and beyond 10,000 events (`EventBuffer` defaults, configurable). |
| Integrity and confidentiality (Art. 5(1)(f), Art. 32) | Delivery requires HTTPS (plain HTTP only for loopback testing). The buffer file is created owner-only on POSIX systems. Errors are logged by type only, never with content. |
| Pseudonymisation (Art. 4(5), Art. 32) | Agent ids are replaced by a keyed HMAC-SHA256 hash. The key comes from `GOV_PSEUDONYM_KEY` or the constructor and is never stored in the buffer. |
| Accuracy (Art. 5(1)(d)) | The matcher uses validators (Luhn, SSN issuance rules) to reduce false positives. Detection precision and recall still have to be measured. |

## What stays personal data

Pseudonymised ids are still personal data under the GDPR, because whoever holds the key can reverse the mapping. The destination host and the classes matched can also relate to an identifiable person once Layer 3 links them to a user or device. Treat the events and the buffer as personal data.

## What the deploying organisation must do

1. **Lawful basis.** Choose and document one (commonly legitimate interests, Art. 6(1)(f), supported by a balancing test) and check national employment-monitoring law. Some countries require works-council involvement or employee consent mechanisms.
2. **DPIA.** Systematic monitoring of employees will normally need a data protection impact assessment (Art. 35).
3. **Transparency.** Tell employees in advance what is monitored, why, what is recorded and for how long (Art. 13/14).
4. **Scope.** Run collectors only on managed devices, and only on devices of people who have been informed. The prototype is for consenting test machines.
5. **Retention.** Set retention for events after delivery to Layer 3, and decide who can access them and for what purpose (security review, not performance management).
6. **Key management.** Generate a random key of at least 16 bytes, keep it outside the repository, restrict who can read it, and rotate it on a schedule. A rotated key makes older ids unlinkable.
7. **Automated decisions.** A block is an automated action. Keep human review and an appeal route for cases that significantly affect a person (Art. 22).
8. **Rights requests.** Be able to find, export and delete events about a person where the law requires it. Because ids are pseudonymised, this needs the key.
9. **Processors and transfers.** If Layer 3 or the model for Layers 4–5 runs with a third party or outside the EEA, put a processing agreement and a transfer mechanism in place.
10. **TLS interception.** The proxy decrypts traffic to the listed AI hosts. Keep that list short, protect the proxy's CA private key, and never install its CA on devices you do not manage.

## Known gaps

- The prototype has no access control on the buffer beyond file permissions.
- The Layer 3 ingestion endpoint is not built yet, so end-to-end retention and deletion are not enforced.
- Fail-open is the default when inspection itself fails (`GOV_FAIL_CLOSED=1` changes this). Choose deliberately.
