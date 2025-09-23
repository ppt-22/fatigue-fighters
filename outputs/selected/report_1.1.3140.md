# Rule Tuning Analysis for Okta MFA Failures Detection

## 1. Rule Statistics:
- **Rule ID**: 1.1.3140
- **Rule Name**: okta [multiple mfa failures]
- **Severity**: medium
- **Search Query**: `class=okta eventtype=user.authentication.auth_via_mfa result=failure not srcipv4:$exclusions.global.srcipv4not srcipv4:[199.187.70.1/24,199.73.1.1/24,199.187.90.0/23,199.187.88.0/23,24.206.71.24]`
- **Events Threshold**: 10
- **Time Window**: 18000 seconds (5 hours)
- **Distinguishers**: ['username']
- **Total Alerts**: 6
- **False Positives**: 6
- **FP Percentage**: 100%

## 2. Identified Patterns:
- All alerts (100%) have been classified as false positives
- The rule is looking for multiple MFA failures for the same user within a 5-hour window
- Current query has two issues:
  1. There's a syntax error in the exclusion logic: `not srcipv4:$exclusions.global.srcipv4not` should have a space before "not"
  2. The rule doesn't account for normal user behavior where legitimate users might experience multiple MFA failures due to typos, expired tokens, or device issues

## 3. Root Cause Analysis:
- The query has a syntax error in the exclusion portion, which may prevent proper filtering of excluded IP addresses
- The current threshold of 10 failures within 5 hours may be too low for legitimate user activity
- There's no consideration for the timespan between failures, which could help distinguish between normal user errors and potential attack patterns
- The rule only distinguishes by username but doesn't consider other contextual factors like geographical location or access patterns

## 4. Rule Modifications:
I recommend the following changes to reduce false positives:

1. Fix the syntax error in the exclusion logic:
```
class=okta eventtype=user.authentication.auth_via_mfa result=failure not srcipv4:$exclusions.global.srcipv4 not srcipv4:[199.187.70.1/24,199.73.1.1/24,199.187.90.0/23,199.187.88.0/23,24.206.71.24]
```

2. Increase the event threshold from 10 to 15 to allow for more legitimate failure attempts:
```
Events Threshold: 15
```

3. Reduce the time window from 5 hours to 2 hours to focus on more concentrated failure attempts that are more indicative of an attack:
```
Seconds Threshold: 7200
```

4. Add additional context by making the rule more specific to detect rapid succession failures which are more indicative of brute force attempts:
```
class=okta eventtype=user.authentication.auth_via_mfa result=failure not srcipv4:$exclusions.global.srcipv4 not srcipv4:[199.187.70.1/24,199.73.1.1/24,199.187.90.0/23,199.187.88.0/23,24.206.71.24] has(client) has(username)
```

## 5. Summary:
The current rule for detecting multiple Okta MFA failures is generating 100% false positives. The main issues include a syntax error in the exclusion logic, low threshold settings, and insufficient context for distinguishing between normal user errors and actual attacks.

By fixing the syntax error, increasing the failure threshold to 15, reducing the time window to 2 hours, and ensuring key fields exist in the events, we can significantly reduce false positives while maintaining detection capability. These changes will improve analyst efficiency by reducing noise and focusing attention on more suspicious patterns of MFA failures that occur in shorter time frames, which are more indicative of brute force attempts rather than legitimate user errors.