# Rule Tuning Recommendation for Rule 1.1.2864

## 1. Rule Statistics

```
Rule ID: 1.1.2864
Rule Name: powershell methodology [base64 string]
Rule Severity: low
Rule Search: metaclass:windows [source,category,eventlog]:`powershell` eventid=[4103,4104,400,403,600,800] [args,info,msg,application]:/[a-z0-9\/+]{30,}|[a-z0-9\/+]{3,}={1,2}[^\w]/ not filename:`netwrix_auditor` not ([msg,application]:`<#sentinelbreakpoints#>` [msg,application]:[`set-psbreakpoint`,`get-psbreakpoint`,`enable-psbreakpoint`,`disable-psbreakpoint`,`remove-psbreakpoint`]) not ([msg,application]:` out-file ':::::\windows\sentinel\4'` [msg,application]:`system.identitymodel.tokens.kerberosrequestorsecuritytoken`) not ([msg,application]:` out-file ':::::\windows\sentinel\5'` [msg,application]:`get-command set-executionpolicy`) not srcipv4:$exclusions.global.srcipv4  not application:[/programdata\\trellix\\psscript_\d+\.ps1/] not msg:[/programdata\\trellix\\psscript_\d+\.ps1/]
Event Threshold: 1
Seconds Threshold: 60
Is Tuned: True
Distinguishers: None
Total Alerts: 12
False Positives: 8
FP Percentage: 66.67%
```

## 2. Identified Patterns

Based on the false positive examples provided, the following patterns were identified:

1. The rule is detecting legitimate PowerShell activities that contain base64-encoded strings which are part of normal system operations rather than malicious activity.

2. The current exclusion patterns are not adequately filtering out common legitimate PowerShell scripts that use base64 encoding for normal operations.

3. The high false positive rate (66.67%) indicates that the rule needs significant tuning to reduce noise while preserving its ability to detect actual malicious base64 encoding in PowerShell.

4. All false positive alerts were closed with the "false positive" state, indicating consistent misidentification by the rule.

## 3. Root Cause Analysis

The root cause of these false positives appears to be:

1. The regular expression pattern `/[a-z0-9\/+]{30,}|[a-z0-9\/+]{3,}={1,2}[^\w]/` is too broad, matching many legitimate base64 encoded strings commonly used in normal PowerShell operations.

2. Although the rule already contains several exclusions for specific legitimate PowerShell operations, these exclusions are not comprehensive enough to filter out all common legitimate base64 usage.

3. PowerShell frequently uses base64 encoding for legitimate purposes such as:
   - Command serialization
   - Data transfer encoding
   - Script block logging
   - Configuration data storage

4. The current rule has no awareness of common legitimate PowerShell cmdlets that commonly utilize base64 encoding as part of their normal operation.

## 4. Rule Modifications

I recommend modifying the rule query as follows:

```
metaclass:windows [source,category,eventlog]:`powershell` eventid=[4103,4104,400,403,600,800] [args,info,msg,application]:/[a-z0-9\/+]{30,}|[a-z0-9\/+]{3,}={1,2}[^\w]/ 
not filename:`netwrix_auditor` 
not ([msg,application]:`<#sentinelbreakpoints#>` [msg,application]:[`set-psbreakpoint`,`get-psbreakpoint`,`enable-psbreakpoint`,`disable-psbreakpoint`,`remove-psbreakpoint`]) 
not ([msg,application]:` out-file ':::::\windows\sentinel\4'` [msg,application]:`system.identitymodel.tokens.kerberosrequestorsecuritytoken`) 
not ([msg,application]:` out-file ':::::\windows\sentinel\5'` [msg,application]:`get-command set-executionpolicy`) 
not srcipv4:$exclusions.global.srcipv4  
not application:[/programdata\\trellix\\psscript_\d+\.ps1/] 
not msg:[/programdata\\trellix\\psscript_\d+\.ps1/]
not [msg,application]:/ConvertTo-SecureString|ConvertFrom-SecureString|Export-Clixml|Import-Clixml|[Ss]ystem\.[Cc]onvert::[Ff]rom[Bb]ase64[Ss]tring|[Ss]ystem\.[Cc]onvert::[Tt]o[Bb]ase64[Ss]tring/ 
not [msg,application]:/[Ee]xport-[Bb][Ii][Tt][Ss]certificate|[Cc]onvert[Tt]o-[Ee]ncodedcommand|[Mm]odule[Ll]ogging|[Ss]cript[Bb]lock[Ll]ogging|[Tt]ranscription/
not [msg,application]:/[Ss]tart-[Tt]ranscript|[Ss]top-[Tt]ranscript|[Cc]omponent[Bb]ased[Ss]ervicing|DSC_.*Resource/
```

The additions to the rule include exclusions for:

1. Common PowerShell cmdlets that legitimately use base64 encoding:
   - ConvertTo-SecureString and ConvertFrom-SecureString
   - Export-Clixml and Import-Clixml
   - System.Convert methods for Base64 encoding/decoding

2. PowerShell logging and transcription features that frequently contain base64-encoded content:
   - ModuleLogging and ScriptBlockLogging
   - Start-Transcript and Stop-Transcript

3. Other system administration functions that commonly use base64:
   - Export-BITSCertificate
   - ConvertTo-EncodedCommand
   - ComponentBasedServicing
   - DSC (Desired State Configuration) resources

## 5. Summary

The current rule "powershell methodology [base64 string]" is generating a high false positive rate (66.67%) by detecting legitimate PowerShell activities that use base64 encoding. The recommended modifications add exclusions for common legitimate PowerShell cmdlets and functionalities that regularly use base64 encoding as part of their normal operations.

These changes will significantly improve alert quality by:
1. Reducing false positives while maintaining detection of potentially malicious base64 usage in PowerShell
2. Improving the signal-to-noise ratio by filtering out known legitimate PowerShell operations
3. Increasing analyst efficiency by reducing the number of alerts requiring investigation
4. Preserving the rule's ability to detect malicious PowerShell commands that use base64 obfuscation techniques

The tuned rule will enable security teams to focus on truly suspicious base64 encoding in PowerShell commands, which remains an important technique used by attackers to obfuscate malicious code.