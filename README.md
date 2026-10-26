# capstone
well figrue this out 

## What each file does 
```policy.py``` - The policy, something someone will have to change accd to their circumstance. No logic. 
- ai_hosts lists the hostnames the egress proxy will inspect.

- data_classes defines what counts as sensitive. Each class has a name, a tier (structured, credential and so on), one or more regex patterns, an optional extra check by name (luhn for card numbers, ssn_valid for SSNs), and a severity.

- rules says what to do when a data class is found, depending on where it’s going. For example, rule R1 says an SSN, card number, AWS key or private key sent to an unapproved or unknown destination should be blocked. R2 warns on emails to unapproved destinations. R3 only logs an SSN or card sent to an approved destination, and R4 raises an alert if a credential goes even to an approved one.

- default_action: log is what happens when no rule matches.

- max_scan_chars caps how much text gets scanned, as a guard against huge inputs.

```common.py``` - shared vocab 
Implements 'Strict' - base model that rejects any field it was not told about. Holds the enums for Action (log, warn, alert, block), Severity, DestStatus (approved, unapproved, unknown) and DestKind (web, api, mcp, agent). Allows for easily comparing severity and strictness 

```schema.py``` - the rules for what a valid policy looks like. It turns the YAML into typed Python objects and refuses anything malformed
- DataClass, When, Rule and Policy are the shapes of each piece of the file. When is a rule’s condition, where every condition given must hold and an omitted one matches anything.

- Validation catches typos in key names, regexes that don’t compile, validator names that don’t exist, duplicate IDs, and rules that reference a data class that isn’t defined.

- Bundle is a Policy plus two extra fields, a hash and a snapshot of destination statuses. This is the compiled form collectors will load.

- uncovered_classes() finds data classes that no rule can ever match, which would silently fall through to the default action.

- KNOWN_VALIDATORS lists the check names the schema accepts. The functions behind them don’t exist yet, and Part 2 adds them.

```loader.py``` - reading and compiling the policy
- load_policy() reads the YAML file and runs it through the schema.

- policy_hash() produces a fingerprint of the policy. It sorts the keys before hashing so the same policy always gives the same hash, and the hash covers only the policy fields, not the bundle extras.

- compile_bundle() builds the Bundle that collectors load, adding the hash and a copy of the registry’s destination statuses. The registry stays the source of truth, and the bundle is a derived copy so collectors can enforce offline.

```test_policy.py``` - They check that the shipped policy loads and that every data class is covered by a rule, that a minimal policy is valid, and that eight different kinds of broken policy are rejected.

```pyproject.toml``` - requirements for the project