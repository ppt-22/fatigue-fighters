# Rule Tuning Analysis: SOAR - Linux Analytics - Brute Force Success

## 1. Rule Statistics:
```
{
  'rule_id': '9999.0.201', 
  'rule_name': 'soar - linux analytics - brute force success', 
  'rule_severity': 'high', 
  'rule_search': 'class:analytics* application=linux_brute_force auth_success:true severity=high', 
  'event_threshold': 1, 
  'sec_threshold': 3600, 
  'is_tuned': False, 
  'distinguishers': ['srchost', 'srcipv4'], 
  'total_alerts': 20, 
  'false_positives': 20, 
  'fp_percentage': 100.0
}
```

## 2. Identified Patterns:
- All alerts (100%) are being classified as false positives
- The common pattern in the false positives involves the username "solarwinds.trellix" and "netauth"
- The source IP address 10.207.53.161 appears consistently in the false positives
- This source IP is actually a NAT'd IP from 10.28.3.31, which is the NSX SolarWinds server
- These are expected activities related to legitimate SolarWinds discovery of AD devices
- User "jyoti topi" is associated with the "solarwinds" username

## 3. Root Cause Analysis:
The rule is designed to detect successful brute force attacks on Linux systems by correlating multiple failed logins followed by a successful login. However, it's triggering on legitimate SolarWinds discovery activities that use the "solarwinds.trellix" and "netauth" usernames. 

SolarWinds legitimately uses multiple connection attempts as part of its AD device discovery process, which can mimic the pattern of a brute force attack followed by success. The analytics engine is interpreting this legitimate activity as malicious.

The rule is not properly excluding known legitimate service accounts that perform actions that may appear similar to brute force attacks.

## 4. Rule Modifications:
Add exclusions for the SolarWinds service account and its associated IP. The modified rule search query should be:

```
class:analytics* application=linux_brute_force auth_success:true severity=high NOT username:["solarwinds.trellix","netauth"] NOT srcipv4:10.207.53.161
```

If the organization uses additional SolarWinds servers or similar monitoring tools that might trigger false positives, consider creating and referencing a list:

```
class:analytics* application=linux_brute_force auth_success:true severity=high NOT username:$solarwinds_service_accounts NOT srcipv4:$solarwinds_servers_ip
```

Where `$solarwinds_service_accounts` would be a list containing "solarwinds.trellix", "netauth", and any other legitimate service accounts, and `$solarwinds_servers_ip` would be a list containing the NAT'd IPs used by SolarWinds servers.

## 5. Summary:
The rule is generating 100% false positives due to legitimate SolarWinds discovery activities being misinterpreted as brute force attacks. By adding specific exclusions for the SolarWinds service accounts ("solarwinds.trellix" and "netauth") and the NAT'd IP address (10.207.53.161), we can eliminate these false positives while maintaining the rule's ability to detect actual brute force attacks.

These modifications will significantly improve alert quality by reducing the false positive rate, allowing security analysts to focus on genuine threats rather than expected system behavior. The changes maintain the rule's security value while improving operational efficiency by filtering out known good activity patterns.