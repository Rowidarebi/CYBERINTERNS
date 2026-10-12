# Detection Backlog

**Project Sentinel · Inject 03 **

| Item | Detail |
|---|---|
| Client | FinServe Digital Bank Ltd |
| Workstream | Security Operations (SOC) |
| Deliverable | `06-DELIVERABLES/SOC/Detection-Backlog.md` |
| Companion documents | `Detection-Surface.md`, `Coverage-Gaps.md` |
| Date | 11 October 2026 |
| Prepared by | SOC Team |
| Status | **Proposed, not deployed.** All KQL is illustrative. None of it has been run against FinServe data or tested, and no results are claimed. |

## 1. Purpose

FinServe has no formal detection engineering backlog (E1 §6). This document proposes nine detections, ranked by priority, that address the gaps in `Coverage-Gaps.md`. Each one states the attack it is meant to catch, the data it needs and whether that data is collected today.

## 2. How to read this backlog

### 2.1 Categories

| Category | Meaning |
|---|---|
| **A — Can be developed now** | The required log source is reported or documented as reaching Sentinel. The detection can be built and validated once read-only access is available. Arrival of the data must still be confirmed. |
| **B — Telemetry first** | The required log source is **not** collected today, or its collection is unknown. The detection cannot work until the prerequisite is met. It is listed so the logic is ready when the data arrives. |

### 2.2 Priority

Priority follows the consequence-based method in `Coverage-Gaps.md` Section 3: what the detection protects and how badly FinServe would be hurt if the activity went unseen. A Category B detection can therefore rank above a Category A one. In practice, Category A detections should be built **at the same time** as the telemetry for Category B is onboarded.

### 2.3 About the KQL in this document

- Table and column names are Microsoft's standard schema names as I understand them. Each query lists its **schema assumptions**; these must be checked in FinServe's workspace before use.
- Values in angle brackets (for example `<breakglass-upn-1>`) are placeholders FinServe must supply.
- Thresholds are starting points, not tuned values.
- **Safe validation:** run queries only in the Logs page with read-only rights, over a short time range first (for example the last 24 hours). Review results with Marcus Ifill. Do not save a query as an analytics rule, create watchlists or change any setting without authorisation.

Evidence references (E1-E9) are as defined in `Detection-Surface.md` Section 2.

## 3. Backlog summary

| Rank | ID | Detection | Category | Required log source | Collected today? | Gap |
|---|---|---|---|---|---|---|
| 1 | DET-01 | Bulk read of customer data from Azure SQL MI | **B** | SQL MI security audit in workspace | **No** (E1 §6, E2 §7) | G1 |
| 2 | DET-02 | Bulk download from the ID document store | **B** | Storage blob logs (`StorageBlobLogs`) | **No** (E2 §7) | G2 |
| 3 | DET-03 | Tampering with security logging, and storage key listing | **A** | Azure Activity (`AzureActivity`) | **Yes — reported** (E2 §7; E5) | G1, G2, G5 |
| 4 | DET-04 | Sign-in by break-glass or Conditional Access-excluded accounts | **A** | Entra ID sign-in logs (`SigninLogs`) | **Yes — reported** (E3 §7; E5) | G5 |
| 5 | DET-05 | Privileged role or privileged group change | **A** | `AzureActivity`, Entra audit (`AuditLogs`) | **Yes — reported** (E2 §7; E5) | G5 |
| 6 | DET-06 | Unexpected login to the Slough settlement SFTP server | **B** | SFTP server syslog in workspace (`Syslog`) | **No** — local only (E1 §6) | G3 |
| 7 | DET-07 | Kubernetes secret access or `exec` into production pods | **B** | AKS audit log (`AKSAudit`) | **No** (E2 §7; E5) | G4 |
| 8 | DET-08 | Domain Admins change and unusual RDP logon to JUMP-01 | **A (conditional)** | Windows Security events (`SecurityEvent`) | **Yes — documented** (E1 §6); event IDs Unknown | G5 |
| 9 | DET-09 | Suspicious inbox rule in finance mailboxes | **A** | Microsoft 365 activity (`OfficeActivity`) | **Yes — reported** (E2 §7; E5) | G5 |

Five detections are Category A (DET-03, -04, -05, -08, -09) and four are Category B (DET-01, -02, -06, -07).

## 4. Category A — can be developed using currently reported data sources

### DET-03 — Tampering with security logging, and storage key listing

| Field | Detail |
|---|---|
| Detection ID and name | DET-03 — Security logging tampering and storage key listing |
| Attack scenario | An attacker with Azure access tries to hide their activity by deleting diagnostic settings, disabling Sentinel rules or connectors, or deleting the workspace. Before downloading documents, they list the storage account keys of `stfinservedocs`. |
| Affected system | `law-sentinel-prod`; diagnostic settings across all subscriptions; `stfinservedocs`, `stfinservetfstate` |
| Required log source | Azure Activity — table `AzureActivity` |
| Currently collected? | **Yes — reported.** Azure Activity connector enabled (E2 §7; E5). Arrival not verified. |
| Detection logic | Alert on any successful delete or change of diagnostic settings, Sentinel analytics rules or data connectors, or the workspace; alert on `listKeys` against the two sensitive storage accounts. |
| Likely false positives | Platform team changes made through Terraform or the portal; the Azure portal and Storage Explorer call `listKeys` automatically when someone opens a storage account. |
| Tuning and validation | Exclude the production pipeline identity only for planned changes; compare against change tickets; review 30 days of history for normal volume before enabling. |
| Dependencies | Read-only workspace access (Q1); list of approved admin and pipeline identities. |
| Priority and justification | **3 — High.** Uses data already collected; partly compensates for G1 and G2 by catching preparatory steps; protects the SOC's own visibility. |

```kql
// DET-03 (illustrative, untested): security logging tampering and key listing.
let sensitiveOperations = dynamic([
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE",
    "MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/DELETE",
    "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE"
]);
let sensitiveStorage = dynamic(["stfinservedocs", "stfinservetfstate"]);
AzureActivity
| where TimeGenerated > ago(1h)
| where ActivityStatusValue in~ ("Success", "Succeeded")
| where OperationNameValue in~ (sensitiveOperations)
    or (OperationNameValue =~ "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
        and _ResourceId has_any (sensitiveStorage))
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId, SubscriptionId
```

**In plain language:** look at the last hour of Azure activity, keep only successful operations, and return any that delete or change logging, delete Sentinel rules or connectors, delete the workspace, or list the keys of the two sensitive storage accounts. **Schema assumptions:** `AzureActivity` with columns `OperationNameValue`, `ActivityStatusValue`, `Caller`, `CallerIpAddress`, `_ResourceId`. Status values may appear as "Success" or "Succeeded"; check which ones the workspace uses.

### DET-04 — Sign-in by break-glass or Conditional Access-excluded accounts

| Field | Detail |
|---|---|
| Detection ID and name | DET-04 — Break-glass and CA-excluded account sign-in |
| Attack scenario | An attacker uses one of the accounts excluded from MFA, legacy-auth blocking and country blocking: the two break-glass Global Administrators, three service accounts, or the FinRecon shared mailbox, which uses IMAP basic authentication (E3 §2). |
| Affected system | Entra ID; `CA-Exclusions-Service` members |
| Required log source | Entra ID sign-in logs — table `SigninLogs` (and `AADNonInteractiveUserSignInLogs` if collected) |
| Currently collected? | **Yes -- reported** for sign-in logs (E2 §7, E3 §7; E5). E7 §1 confirms both `SigninLogs` and `AADNonInteractiveUserSignInLogs` are collected (C), so non-interactive sign-ins are available. Whether service-principal sign-ins (`AADServicePrincipalSignInLogs`) are also included: Unknown (Q12). |
| Detection logic | Any break-glass sign-in → alert (high severity). Other excluded accounts → alert when the IP address, country or client application differs from that account's known pattern (for FinRecon: IMAP from its known source only). |
| Likely false positives | Planned break-glass tests; service accounts running from new infrastructure after a change. |
| Tuning and validation | Build a 30-day baseline of IP and client app per excluded account first; confirm the break-glass rule FinServe says already exists (E2 §4) and check it covers both accounts. |
| Dependencies | The member list of `CA-Exclusions-Service` from Marcus; Q12. |
| Priority and justification | **4 — High.** These accounts bypass FinServe's main identity controls, and two hold permanent Global Administrator. The data is already collected. |

```kql
// DET-04 (illustrative, untested): sign-ins by accounts excluded from Conditional Access.
// Replace placeholders with the real UPNs, in lower case.
let breakGlass = dynamic(["<breakglass-upn-1>", "<breakglass-upn-2>"]);
let caExcluded = dynamic(["<service-account-1>", "<service-account-2>", "<service-account-3>", "<finrecon-mailbox-upn>"]);
SigninLogs
| where TimeGenerated > ago(1h)
| extend Upn = tolower(UserPrincipalName)
| where Upn in (breakGlass) or Upn in (caExcluded)
| extend IsBreakGlass = Upn in (breakGlass)
| project TimeGenerated, UserPrincipalName, IsBreakGlass, IPAddress, Location,
          AppDisplayName, ClientAppUsed, ResultType, ConditionalAccessStatus
```

**In plain language:** take the last hour of sign-ins, keep only the excluded accounts, and flag whether each one is a break-glass account. `ResultType` "0" means the sign-in succeeded. For the non-break-glass accounts, a second step (not shown) compares `IPAddress` and `ClientAppUsed` with the 30-day baseline. **Schema assumptions:** standard `SigninLogs` columns as named. Legacy IMAP sign-ins are expected to show a `ClientAppUsed` value such as "IMAP4"; confirm this in the data.

### DET-05 — Privileged role or privileged group change

| Field | Detail |
|---|---|
| Detection ID and name | DET-05 -- Privileged role or group change outside change control |
| Replaces | **CUST-02** ("Privileged role assignment outside change window"), which has inverted KQL logic: its `between` clause keeps events **inside** 09:00-17:00 rather than outside it, alerting on legitimate daytime changes and missing out-of-hours ones (E8 §2). CUST-02 generated 9 incidents in 30 days, all closed as informational (E9 §2). It should be disabled when DET-05 is deployed. |
| Attack scenario | An attacker who has gained an admin session gives themselves standing privilege: a new Owner role assignment on `sub-prod` or the tenant root, a new Entra directory role, or a new member in one of the Entra groups that hold Azure RBAC roles. Access is granted to groups, not individuals (E2 §4), so group membership is where privilege actually changes. |
| Affected system | Azure RBAC (tenant root, `sub-prod`, `sub-sandbox`); Entra directory roles; privileged Entra groups |
| Required log source | `AzureActivity` and Entra audit logs — table `AuditLogs` |
| Currently collected? | **Yes — reported** (E2 §7; E5). |
| Detection logic | Alert on role assignment writes in Azure, on members added to Entra roles (including permanent assignments outside PIM), and on members added to a named list of privileged groups. |
| Likely false positives | Legitimate access requests handled by the platform team via ticket; joiners and movers. |
| Tuning and validation | Correlate with ticket records; start as a daily report before making it an alert. Since PIM is not configured (E2 §4), every assignment is permanent, so all changes are in scope. |
| Dependencies | Names of the Entra groups that hold Owner and Contributor roles (from Adeola Balogun or Marcus). |
| Priority and justification | **5 — High.** Standing privilege without PIM means one unauthorised change gives lasting control of production; the data is already collected. |

```kql
// DET-05 (illustrative, untested): privileged role and group changes.
let privilegedGroups = dynamic(["<owner-tenant-root-group>", "<owner-sub-prod-group>", "<contributor-sub-prod-group>"]);
let azureRoleChanges = AzureActivity
    | where TimeGenerated > ago(1h)
    | where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
    | where ActivityStatusValue in~ ("Success", "Succeeded")
    | project TimeGenerated, Source = "Azure RBAC", Actor = Caller, Target = _ResourceId;
let entraRoleChanges = AuditLogs
    | where TimeGenerated > ago(1h)
    | where OperationName in ("Add member to role", "Add member to role outside of PIM (permanent)")
    | project TimeGenerated, Source = "Entra role",
              Actor = tostring(InitiatedBy.user.userPrincipalName),
              Target = tostring(TargetResources[0].userPrincipalName);
let groupChanges = AuditLogs
    | where TimeGenerated > ago(1h)
    | where OperationName == "Add member to group"
    | where tostring(TargetResources) has_any (privilegedGroups)
    | project TimeGenerated, Source = "Privileged group",
              Actor = tostring(InitiatedBy.user.userPrincipalName),
              Target = tostring(TargetResources[0].userPrincipalName);
union azureRoleChanges, entraRoleChanges, groupChanges
```

**In plain language:** collect three kinds of privilege change from the last hour — Azure role assignments, Entra role additions and additions to named privileged groups — and list them together with who made the change. **Schema assumptions:** in `AuditLogs`, the person who made the change is in `InitiatedBy.user` (changes made by an application appear under `InitiatedBy.app` instead), and the group name appears somewhere in `TargetResources`; the simple text match on `TargetResources` is deliberately broad and should be refined after looking at real records.

### DET-08 — Domain Admins change and unusual RDP logon to JUMP-01

| Field | Detail |
|---|---|
| Detection ID and name | DET-08 — Domain Admins membership change and new RDP logon pattern on JUMP-01 |
| Attack scenario | An attacker adds an account to Domain Admins or another privileged AD group; or logs on to JUMP-01, the single administrative route into production (E1 §4), with an account or from an address not seen before. The 6 Domain Admins also use these accounts for day-to-day work (E3 §2), which raises the chance of credential theft. |
| Affected system | Domain controllers (`finserve.local`); JUMP-01 |
| Required log source | Windows Security events via Azure Monitor Agent — table `SecurityEvent` |
| Currently collected? | **Yes -- documented** (E1 §6; E7 §2). **Partly confirmed:** E7 §2 states the data collection rule (`dcr-security-events-common`) uses the **Common** event set on all four hosts (DC-01, DC-02, JUMP-01, ENTRACONNECT-01). The Common set includes event IDs 4728, 4732, 4756 (group membership changes) and 4624 (logon events, including RDP type 10), so both queries in this detection should work (I). However, E7 §5 notes that "several event IDs relevant to credential access are outside" the Common set; Kerberos events (4768, 4769, 4771) used in credential-theft detections are likely excluded. This detection does not depend on them, but future credential-access detections would need the event set upgraded to All. |
| Detection logic | Query 1: alert on any member added to Domain Admins, Enterprise Admins, Schema Admins or Administrators. Query 2: list RDP logons (logon type 10) to JUMP-01 and alert on user/source-IP pairs not seen in the previous 14 days. |
| Likely false positives | Approved admin changes; infrastructure staff working from a new home address; IP address translation hiding the real source. |
| Tuning and validation | Confirm the event IDs are present first; check what source address JUMP-01 records for RDP from the allowlisted addresses. |
| Dependencies | Q10; list of approved admin accounts. |
| Priority and justification | **8 — Medium–High.** Protects tier-0 identity and the production admin route; depends on an unconfirmed collection setting. |

```kql
// DET-08 query 1 (illustrative, untested): privileged AD group membership changes.
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4728, 4732, 4756)
| where TargetUserName in~ ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| project TimeGenerated, Computer, EventID, GroupName = TargetUserName,
          AddedMember = MemberName, ChangedBy = SubjectUserName
```

```kql
// DET-08 query 2 (illustrative, untested): RDP logons to JUMP-01 not seen in the previous 14 days.
let known = SecurityEvent
    | where TimeGenerated between (ago(15d) .. ago(1d))
    | where Computer startswith "JUMP-01" and EventID == 4624 and LogonType == 10
    | distinct TargetUserName, IpAddress;
SecurityEvent
| where TimeGenerated > ago(1d)
| where Computer startswith "JUMP-01" and EventID == 4624 and LogonType == 10
| join kind=leftanti known on TargetUserName, IpAddress
| project TimeGenerated, TargetUserName, IpAddress, Computer
```

**In plain language:** query 1 lists anyone added to a powerful AD group. Query 2 builds a list of who normally logs on to JUMP-01 over RDP and from where, then shows any logon in the last day that is not on that list. **Schema assumptions:** for group-change events, `TargetUserName` holds the group name and `MemberName` the added account; the JUMP-01 computer name begins with "JUMP-01".

### DET-09 — Suspicious inbox rule in finance mailboxes

| Field | Detail |
|---|---|
| Detection ID and name | DET-09 — Forwarding, redirect or delete inbox rule created |
| Attack scenario | After stealing a mailbox session, an attacker creates an inbox rule that forwards, redirects, moves or deletes messages, to hide replies or intercept payment confirmations. Settlement confirmations reach FinRecon through an Exchange shared mailbox (E4 §4), so finance mailboxes are a natural target. External auto-forwarding is blocked by policy (E3 §3), but inbox rules that move or delete mail are not. |
| Affected system | Exchange Online — Finance Operations mailboxes and the FinRecon shared mailbox |
| Required log source | Microsoft 365 activity — table `OfficeActivity` |
| Currently collected? | **Yes — reported** (Microsoft 365 connector, E2 §7; E5). Whether inbox-rule events are included: confirm in the data. |
| Detection logic | Alert when an inbox rule is created or changed with forward, redirect, delete or move actions; raise severity for finance users and the FinRecon mailbox. |
| Likely false positives | Users organising their own mail with move rules. |
| Tuning and validation | Start with forward/redirect/delete only; add "move" for finance mailboxes only; review 30 days of history. |
| Dependencies | List of Finance Operations mailboxes. |
| Priority and justification | **9 — Medium.** A common business email compromise technique on a mailbox that is part of the settlement process; data is already collected. |

```kql
// DET-09 (illustrative, untested): inbox rules that forward, redirect, delete or move mail.
OfficeActivity
| where TimeGenerated > ago(1h)
| where OfficeWorkload == "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "DeleteMessage", "MoveToFolder")
    or OperationProperties has_any ("Forward", "Redirect", "Delete", "MoveToFolder")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters, OperationProperties
```

**In plain language:** look for new or changed inbox rules in the last hour that forward, redirect, delete or move mail. **Schema assumptions:** rules created with PowerShell or Outlook on the web record their settings in `Parameters`; rules created from the Outlook desktop client (`UpdateInboxRules`) record them in `OperationProperties`. Check both fields exist in the workspace.

## 5. Category B — requires telemetry onboarding or verification first

### DET-01 — Bulk read of customer data from Azure SQL MI

| Field | Detail |
|---|---|
| Detection ID and name | DET-01 -- Unusual volume of customer data read from `sqlmi-prod` |
| Replaces | **CUST-03** ("Database mass export"), which queries the table `SQLSecurityAuditEvents`. This table does not exist in the workspace because the SQL audit connector has never been enabled (E7 §1; E8 §2). CUST-03 has produced zero alerts since deployment (E9 §2). It should be disabled now and replaced by DET-01 once the prerequisite data is onboarded. |
| Attack scenario | An attacker uses a stolen connection string (five AKS services keep them as Kubernetes secrets, E2 §2) or the UAT-to-production path (E1 §3.1) to extract customer and transaction records. |
| Affected system | Azure SQL MI `sqlmi-prod` |
| Required log source | SQL security audit events in the workspace (expected in `AzureDiagnostics` with Category `SQLSecurityAuditEvents`) |
| Currently collected? | **No.** Audit goes to storage only (E1 §6; E2 §7; E5). |
| **Missing prerequisite** | Send SQL MI audit events to `law-sentinel-prod` (G1), with action groups that record completed statements and row counts. |
| Detection logic | Alert when a single database principal reads more rows than its normal baseline in a short window, or when an application's service login is used from an unexpected client IP. |
| Likely false positives | Batch jobs, statement generation, reporting queries, the nightly UAT refresh (02:00, E4 §2). |
| Tuning and validation | Build a per-principal baseline over 14–30 days after onboarding; exclude known batch windows by principal, not by time alone. |
| Dependencies | G1 closed; Q7 (audit action groups). |
| Priority and justification | **1 — Critical.** Protects the largest store of customer and transaction data; there is currently no detection for it in Sentinel. |

```kql
// DET-01 (illustrative, untested; needs SQL audit in the workspace first).
let rowThreshold = 10000;   // starting point only; replace with a baseline
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "SQLSecurityAuditEvents"
| where action_name_s in ("BATCH COMPLETED", "RPC COMPLETED")
| summarize RowsRead = sum(affected_rows_d), Statements = count(), SampleStatement = take_any(statement_s)
    by server_principal_name_s, client_ip_s, database_name_s, bin(TimeGenerated, 15m)
| where RowsRead > rowThreshold
```

**In plain language:** add up how many rows each database login touched in 15-minute blocks over the last hour, and show any login that touched more than the threshold, with an example statement. **Schema assumptions:** SQL MI audit records in `AzureDiagnostics` with suffixed column names (`_s` for text, `_d` for numbers) as shown. The exact table and column names depend on how the diagnostic setting is configured and must be checked once data arrives.

### DET-02 — Bulk download from the ID document store

| Field | Detail |
|---|---|
| Detection ID and name | DET-02 — Unusual number of documents downloaded from `stfinservedocs` |
| Attack scenario | An attacker with a SAS token, account key or application identity downloads large numbers of passport and licence images. |
| Affected system | Storage account `stfinservedocs` (and `stfinservetfstate` for any read) |
| Required log source | Blob diagnostic logs — table `StorageBlobLogs` |
| Currently collected? | **No.** Storage diagnostics not enabled (E2 §7; E5). |
| **Missing prerequisite** | Enable blob read/write/delete logging to the workspace (G2), after a volume estimate. |
| Detection logic | Alert when one caller downloads more distinct documents in 15 minutes than its baseline; alert on any read of `stfinservetfstate` by an identity other than the Terraform pipeline. |
| Likely false positives | The statements service and onboarding service reading documents as part of normal processing; backup or migration jobs. |
| Tuning and validation | Baseline by caller identity and authentication type; treat account-key access from outside known services as high severity. |
| Dependencies | G2 closed; Q11. |
| Priority and justification | **2 — Critical.** Identity documents for the whole customer base; no detection exists today. |

```kql
// DET-02 (illustrative, untested; needs blob logging in the workspace first).
let blobThreshold = 500;   // starting point only; replace with a baseline
StorageBlobLogs
| where TimeGenerated > ago(1h)
| where AccountName == "stfinservedocs"
| where OperationName == "GetBlob" and StatusText == "Success"
| summarize Downloads = count(), DistinctBlobs = dcount(Uri), Bytes = sum(ResponseBodySize)
    by CallerIpAddress, AuthenticationType, RequesterObjectId, bin(TimeGenerated, 15m)
| where DistinctBlobs > blobThreshold
```

**In plain language:** count how many different documents each caller downloaded in 15-minute blocks, and show callers above the threshold, with how they authenticated. **Schema assumptions:** standard `StorageBlobLogs` columns as named. `CallerIpAddress` may include a port number; `RequesterObjectId` is empty for key or SAS access, which is itself useful to note.

### DET-06 — Unexpected login to the Slough settlement SFTP server

| Field | Detail |
|---|---|
| Detection ID and name | DET-06 — SFTP server login outside the settlement window or from a new source |
| Attack scenario | An attacker logs in to the DC-SLO SFTP server to read or alter the end-of-day settlement file between the 23:30 extract and the 00:15 delivery (E4 §4), or tries to guess passwords. |
| Affected system | DC-SLO SFTP server |
| Required log source | SFTP server authentication logs in the workspace — expected table `Syslog` |
| Currently collected? | **No.** Local syslog only, 30 days (E1 §6). |
| **Missing prerequisite** | Forward the server's authentication and transfer logs to the workspace (G3). The server's operating system and SFTP software are Unknown (Q8). |
| Detection logic | Alert on successful logins outside the nightly settlement window (UK time), from source addresses not seen before, and on bursts of failed logins. |
| Likely false positives | Corebridge's own extract delivery; Finance Operations using the manual fallback (E6); maintenance by infrastructure staff. |
| Tuning and validation | Agree the expected accounts and sources with Tobi Okonkwo and Nadia Ferreira; allow for UK summer time (Sentinel stores UTC). |
| Dependencies | G3 closed; Q8; Slough SME session before the Head of Infrastructure leaves. |
| Priority and justification | **6 — High.** Protects settlement data on an unattended process with a long-lived credential. |

```kql
// DET-06 (illustrative, untested; needs SFTP server logs in the workspace first).
// Assumes a Linux OpenSSH server. Times are UTC; the settlement window is UK time.
Syslog
| where TimeGenerated > ago(1h)
| where Computer has "<sftp-server-name>"
| where ProcessName in ("sshd", "internal-sftp")
| where SyslogMessage has_any ("Accepted password", "Accepted publickey", "Failed password")
| extend Outcome = iff(SyslogMessage has "Accepted", "Success", "Failure")
| extend HourUtc = datetime_part("hour", TimeGenerated)
| project TimeGenerated, HourUtc, Computer, Outcome, SyslogMessage
```

**In plain language:** show successful and failed SSH/SFTP logins on the settlement server over the last hour, with the hour of day so logins outside the settlement window stand out. **Schema assumptions:** a Linux OpenSSH server sending to `Syslog`. If the server runs Windows or other SFTP software, the table and message text will be different and the query must be rewritten.

### DET-07 — Kubernetes secret access or `exec` into production pods

| Field | Detail |
|---|---|
| Detection ID and name | DET-07 — Human access to Kubernetes secrets or interactive shell in a production pod |
| Attack scenario | An attacker with cluster access reads the Kubernetes secrets that hold SQL connection strings (E2 §2), or opens a shell inside the payments service with `kubectl exec`. |
| Affected system | AKS production cluster |
| Required log source | AKS audit log — table `AKSAudit` (resource-specific) or `AzureDiagnostics` category `kube-audit` |
| Currently collected? | **No.** AKS audit log not enabled (E2 §7; E5); see discrepancy X1. |
| **Missing prerequisite** | Enable the full `kube-audit` category (G4). The lower-volume `kube-audit-admin` category leaves out `get` and `list` requests, so it would **not** record secret reads. |
| Detection logic | Alert on `get`/`list` of secrets and on `exec` requests by any identity that is not a system component or known deployment identity. |
| Likely false positives | Platform engineers troubleshooting; the deployment pipeline; operators and controllers that legitimately read secrets. |
| Tuning and validation | Baseline the identities that read secrets; exclude by identity, not by namespace. |
| Dependencies | G4 closed; Q5. |
| Priority and justification | **7 — High.** Production services including payments; a credential path into G1. |

```kql
// DET-07 (illustrative, untested; needs AKS audit in the workspace first).
AKSAudit
| where TimeGenerated > ago(1h)
| extend Actor = tostring(User.username),
         Resource = tostring(ObjectRef.resource),
         Subresource = tostring(ObjectRef.subresource)
| where (Resource == "secrets" and Verb in ("get", "list"))
     or (Resource == "pods" and Subresource == "exec")
| where not(Actor startswith "system:")
| project TimeGenerated, Actor, Verb, Resource, Subresource,
          Namespace = tostring(ObjectRef.namespace), Name = tostring(ObjectRef.name), SourceIps
```

**In plain language:** show every read of a Kubernetes secret, and every attempt to open a shell inside a pod, made by anything other than Kubernetes' own system accounts. **Schema assumptions:** resource-specific `AKSAudit` table with `User`, `ObjectRef`, `Verb` and `SourceIps`. If the diagnostic setting sends to `AzureDiagnostics` instead, the query must be rewritten to parse the audit record.

## 6. Dependencies across the backlog

| Dependency | Needed for | Owner | Status |
|---|---|---|---|
| Read-only Sentinel and Log Analytics access | All detections | Marcus Ifill | Requested (Q1) |
| Analytics rule inventory | Avoid duplicating existing rules | Marcus Ifill | Requested (Q2) |
| SQL MI audit in workspace | DET-01 | Platform team, after authorisation | Not started (G1) |
| Blob logging in workspace | DET-02 | Platform team, after authorisation | Not started (G2) |
| SFTP server logs in workspace | DET-06 | Infrastructure, after authorisation | Not started (G3) |
| AKS full audit in workspace | DET-07 | Platform team, after authorisation | Not started (G4) |
| Windows event IDs confirmed | DET-08 | Marcus Ifill | **Partly resolved** (E7 §2: Common set confirmed; group-change and logon IDs are included) |
| Non-interactive sign-ins confirmed | DET-04 | Marcus Ifill | **Resolved** (E7 §1: `AADNonInteractiveUserSignInLogs` collected). Service-principal sign-ins still Unknown (Q12) |
| Lists: CA-excluded accounts, privileged groups, finance mailboxes, admin accounts | DET-04, -05, -08, -09 | Marcus Ifill / platform team | Not yet requested |

## 7. What this backlog does not cover

- Detections for third-party systems (G6): these need supplier telemetry first.
- Branch firewall detections (G8): device capability is Unknown.
- Customer authentication and fraud detections: no customer authentication log source is documented (G10).
- Tuning of the existing 847-alert workload, which should run in parallel (`Coverage-Gaps.md` Section 7).
