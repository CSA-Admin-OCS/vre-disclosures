+++
title = "VRE-0003-display-name-spoofing"
date = 2026-10-29
+++


| Field | Value |
|---|---|
| VRE ID | VRE-0003 |
| Author | ex1stencee |
| VRE | VRE Team |
| Date | 2026-10-09 |
| Severity | High |
| Status | In Progress |
| Affected Product | Spring |
| Affected Project | Group Chat |


## Description

Group chat verifies which user is logged into the chat using their display name, which can be editted through the profile settings.


## Impact

The group chat service currently uses display names in order to verify which user has permissions to edit and delete messages.

Entire extent of impact is unknown, as other projects may also incorrectly use display names for verification.


## Proof of Concept (PoC)

Display names are edited through the profile settings page at `https://pages.opencodingsociety.com/profile`. Delete requests can be sent like so:

```
curl -sS -i -X DELETE --cookie "jwt_java_spring=$TOKEN" https://spring.opencodingsociety.com/api/groups/chat/group-id/messages/message-id>
```

## Suggested Fix (Optional)

[Describe the recommended remediation or mitigation, if known.]

[Optional code example or configuration change]


## References (Optional)

[Related documentation, advisories, tickets, or CVEs]


## Notes (Optional)

[Any additional context, limitations, or follow-up information.]
