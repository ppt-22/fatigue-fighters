# Rule Tuning Analysis for Okta MFA Failures Rule

## 1. Rule Statistics
```
{
  "rule_id": "N/A",
  "rule_name": "okta [multiple mfa failures]",
  "total_alerts": 3,
  "false_positives": 3,
  "fp_percentage": 100.0
}
```

## 2. Identified Patterns
- All alerts were classified as false positives with no specific closing reason documented
- The rule is triggering on standard authentication failure patterns that are likely benign user behavior
- Failures appear to be related to normal MFA authentication attempts where users might have entered incorrect codes or experienced temporary verification issues
- Current rule logic lacks sufficient context to differentiate between normal authentication retry patterns and actual attack scenarios
- The rule doesn't consider user behavior patterns, time windows, or geographic locations of authentication attempts

## 3. Root Cause Analysis
The rule is triggering incorrectly because:
- The base query is too broad, capturing any Okta MFA failures without sufficient context
- The search query uses a simple exclusion list (`$exclusions.global.srcipv4`) but doesn't account for common legitimate MFA failure scenarios
- The rule doesn't establish thresholds for number of failures in a specific time window per user
- It doesn't analyze the context of the MFA failures such as:
  - Time between attempts
  - Successful logins following failed attempts
  - Geographic dispersion of access attempts
  - Common user error patterns
- There's no exclusion for specific user accounts that might legitimately have higher MFA failure rates

## 4. Recommended Rule Modifications
I recommend modifying the search query to add more specificity and context to reduce false positives:

```
class=okta eventtype=user.authentication.auth_via_mfa result=failure 
not srcipv4:$exclusions.global.srcipv4 
not srcipv4:[199.187.70.1/24,199.73.1.1/24,199.187.90.0/23,199.187.88.0/23,24.206.71.24]
not reason="VERIFICATION_CODE_INVALID" 
not reason="PASSCODE_INVALID"
| groupby [userid] as num_failures
| filter num_failures > 3
```

Additionally, add a tuning_search parameter to identify repeated failures from the same source:

```
class=okta eventtype=user.authentication.auth_via_mfa result=failure 
| groupby [srcipv4, userid] as ip_user_failures 
| filter ip_user_failures > 3
```

## 5. Summary
The current Okta MFA failure rule is generating 100% false positives due to its overly broad detection criteria. The rule is triggering on normal user authentication behaviors where MFA verification occasionally fails.

The recommended modifications add contextual filtering to exclude common verification code errors and implement grouping by user ID with a minimum threshold of failures. These changes will drastically reduce false positives while maintaining detection capability for actual attack scenarios where multiple MFA failures indicate potential account takeover attempts. This will improve analyst efficiency by reducing alert noise and allowing them to focus on genuine security threats rather than normal authentication patterns.