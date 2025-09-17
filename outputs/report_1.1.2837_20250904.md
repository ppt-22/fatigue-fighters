# Proofpoint TAP [Message Delivered - Attachment/Text Threat] Rule Analysis

## 1. Rule Statistics
- **Rule ID**: N/A (Not provided in the data)
- **Rule Name**: proofpoint tap [message delivered - attachment/text threat]
- **Total Alerts**: 3
- **False Positives**: 3
- **FP Percentage**: 100%

## 2. Identified Patterns
After analyzing the false positive examples, I note the following patterns:

1. All alerts were generated within a short timeframe on 2025-06-24, with timestamps at 19:00:00.709239Z, 19:00:01.851880Z, and 19:34:38.894245Z.

2. All alerts were marked as false positives without specific closing reasons.

3. The rule is focused on Proofpoint TAP message delivery events containing malicious attachments or text-based threats but appears to be triggering on benign events.

4. The current rule is structured to exclude URL threats but doesn't have granular filtering for attachment/text threat classifications.

## 3. Root Cause Analysis

The root cause appears to be insufficient filtering in the rule's search query:

1. The current rule query `class=proofpoint_siemapi eventtype:'msgdlv*' not threat=url not srcipv4:$exclusions.global.srcipv4` is designed to identify Proofpoint TAP message delivery events with attachment or text threats.

2. However, it's not properly distinguishing between legitimate vs. malicious attachments/text, resulting in false positives.

3. The rule lacks filters for severity, threat type classification, or specific threat scores that would help identify truly malicious deliveries versus benign ones.

4. The existing exclusion (`not srcipv4:$exclusions.global.srcipv4`) may not be comprehensive enough to exclude known safe sources.

## 4. Recommended Rule Modifications

I recommend the following modifications to the search query to reduce false positives:

```
class=proofpoint_siemapi 
eventtype:'msgdlv*' 
not threat=url 
not srcipv4:$exclusions.global.srcipv4 
(threat_score > 75 OR threat_severity:["high", "critical"] OR malwaretype:["trojan", "exploit", "backdoor", "keylogger", "spyware", "ransomware"])
```

If there's a specific list of trusted senders or known-good domains within your organization, consider adding further exclusions:

```
not from:$trusted_senders
not domain:$trusted_domains
```

Alternatively, if you're looking for specific patterns in the message content to filter false positives, consider:

```
not msg:/regular business email pattern/
```

## 5. Summary

The Proofpoint TAP rule for message delivery events with attachment/text threats is generating 100% false positives. The current query lacks sufficient filtering criteria to distinguish between legitimate business communications and actual threats.

By adding threshold filtering based on threat score, severity, and malware classifications, we can significantly reduce false positives while maintaining detection capability for genuine threats. These modifications will improve analyst efficiency by focusing attention on higher-risk message delivery events that have a greater likelihood of being true positives.

Consider implementing a tuning period after these changes to validate the effectiveness of the modifications and make further adjustments if necessary.