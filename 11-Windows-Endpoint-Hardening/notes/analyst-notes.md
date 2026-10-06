# Analyst notes

This case documents my learning as a junior/student analyst. I used the recorded lab conversation only; I did not rerun commands on the personal endpoint while preparing this publication.

## Lessons learned

- A listening port, a firewall Allow rule and remote reachability are different observations.
- `Any` applies across firewall profiles. It deserves a requirements review rather than an automatic malicious classification.
- An unfamiliar service or account name is a starting point for investigation.
- A path under System32 or Program Files is useful context, not proof of authenticity.
- Account enabled status, group membership and effective session privileges are separate checks.
- A PID can be reused. Match host, timestamp and process name/path before relating historical events.
- No search results can leave a question unresolved; they do not justify inventing a process ancestor.
- Password policy measures enforcement, not the strength of existing passwords.

## Limits and outstanding work

The full host baseline, neighbor inventory and all raw exports are not reproduced. No patch compliance, binary signatures/hashes, end-to-end firewall reachability or completed remediation is claimed. CodexSandboxOnline membership was checked, but its creator was not conclusively identified. The initial Edge ancestor remained unresolved.

The network profile changed from Public to Private in the recorded practice and the firewall remained enabled on all three profiles. That change is not a general hardening recommendation: Private can permit more local functions and requires a trusted network context.

The follow-up privilege-auditing exercise was completed: Sin auditoría changed to Aciertos, Splunk detected 4674, and rex extracted the fields. PID 0x4e8 (1256) was linked to active lsass. No matching 4688 was found in 30 minutes; earlier startup remains probable, not verified. Classification: TP / Benign. The SPL file distinguishes recorded searches from broader unexecuted follow-up searches.

## Review before merge

Confirm the case wording matches the lab experience. Review the selected evidence and recommendations. Publish through a reviewed branch/PR; do not attach unsanitized screenshots or command-line exports.
