# Detection Surface Map

**Project Sentinel · Inject 03 **

| Item | Detail |
|---|---|
| Client | FinServe Digital Bank Ltd |
| Workstream | Security Operations (SOC) |
| Deliverable | `06-DELIVERABLES/SOC/Detection-Surface.md` |
| Companion documents | `Coverage-Gaps.md`, `Detection-Backlog.md` |
| Date | 11 October 2026 |
| Prepared by | SOC Team |
| Status | **Provisional.** Based on architecture documents and information reported by the Security Operations Manager. No access to the Sentinel workspace has been granted, no queries have been run and no detection has been tested. |

## 1. Purpose and scope

This map records, for every system documented in FinServe's architecture, whether it produces security-relevant telemetry, whether that telemetry reaches Microsoft Sentinel (workspace `law-sentinel-prod` in `sub-management`), how long the data is kept, and whether any analytics rule could raise an alert from it.

It answers the SOC question **"If an attacker acted on this system, would FinServe see it, and for how long could we look back?"** It is organised by infrastructure area so it can be compared line by line with the GRC asset register.

In scope: Azure (all six subscriptions), identity and administration, Microsoft 365 and endpoints, network devices, the legacy Slough data centre (DC-SLO) and the third parties whose systems handle FinServe data.

Out of scope: testing or changing any configuration. This is a documentary assessment; the validation steps needed to confirm it are listed in Section 6.

## 2. Evidence sources

| Ref | Source | Sections used | Evidence type |
|---|---|---|---|
| E1 | `02-ARCHITECTURE/01-Network-Diagram.md` | §1 Sites, §2 Topology, §3 Segmentation, §4 Remote access, §5 Egress, **§6 Logging and telemetry**, §8 Known debt | FinServe documentation |
| E2 | `02-ARCHITECTURE/02-Azure-Architecture.md` | §1 Subscriptions, §2 Production workload, §3 Data services, §4 Identity, §5 IaC, **§7 Logging and telemetry** | FinServe documentation |
| E3 | `02-ARCHITECTURE/03-M365-Architecture.md` | §1 Licensing, §2 Identity, §3 Exchange, §5 DLP, §6 Endpoint, **§7 Logging and telemetry**, §9 Known debt | FinServe documentation |
| E4 | `02-ARCHITECTURE/04-Data-Flow.md` | §1 Data categories, §2 Flows, §3 Third parties, §4 Reconciliation path, §5 Cross-border transfer | FinServe documentation |
| E5 | Inject 03 briefing from Marcus Ifill, Security Operations Manager | Connectors, analytics rules, alert statistics, retention, known concerns | Client statement |
| E6 | `01-CLIENT/01-Company-Profile.md` §2; `01-CLIENT/02-Organisation-Chart.md` §4, §6, §7; `01-CLIENT/03-Business-Processes.md` §4; `01-CLIENT/04-Stakeholders.md` §4 | Branch customers, security team size, device allocation, settlement process, SME context | FinServe documentation |
| E7 | `04-SOC/Logs/Log-Source-Inventory.md` | §1 Sentinel data connectors, §2 Hosts forwarding to workspace, §3 Systems with no telemetry, §4 Retention, §5 Known limitations | SOC internal documentation |
| E8 | `04-SOC/Alerts/Analytics-Rules.md` | §1 Built-in templates, §2 Custom rules (CUST-01 to CUST-04), §3 Automation, §4 Suppression and tuning, §5 Coverage assessment | SOC internal documentation |
| E9 | `04-SOC/Alerts/Alert-Summary-30-Days.md` | §1 Headline, §2 By rule, §3 The four investigated, §4 Working pattern, §5 SOC Manager notes | SOC internal documentation |

The architecture README states that these documents describe the estate "in the voice of the people who built it" and that confident phrasing should be treated "as a claim to be tested". This map follows that instruction. The SOC internal documents (E7-E9) describe what Security Operations believes it has and how it operates; where they conflict with the architecture documents, the discrepancy is a finding.

## 3. Coverage status definitions

### 3.1 Evidence classification

| Class | Meaning |
|---|---|
| **Confirmed (C)** | Explicitly stated in the supplied documentation. This confirms what FinServe has documented, not what is running in the tenant. |
| **Reported (R)** | Stated by Marcus Ifill or another client representative, not independently verified. |
| **Inferred (I)** | A reasonable technical interpretation; the reasoning is given in the cell or in Section 5. |
| **Unknown (U)** | Insufficient evidence. Shown as **Unknown — validation required**. |

### 3.2 Column values

| Column | Values used |
|---|---|
| Security-Relevant Telemetry | What the system can record that matters for detection or investigation. |
| Reaches Sentinel? | **Yes (documented)** — the documents say it is collected; arrival not verified · **Partial** — only some log categories · **No** — documented as not collected or kept locally · **Unknown — validation required** |
| Retention | Where the data is kept and for how long. Workspace retention and source-system retention are shown separately; 60 days is applied only to data documented as reaching the workspace. |
| Analytics Rule Coverage | **Template (reported)** — Marcus reports built-in templates enabled for this source family · **Specific rule (documented)** · **None reported** — data reportedly arrives but no rule is reported for it · **Not possible** — the data is not in Sentinel · **Unknown — validation required** |

### 3.3 The six conditions are not the same thing

A system is only effectively monitored if all six conditions hold. The documents can support conditions 1, 2 and 4; conditions 3, 5 and 6 need workspace access.

| # | Condition | What the current evidence can show |
|---|---|---|
| 1 | The system **generates** security logs | Usually documented (C) |
| 2 | Collection is **configured** | Documented as a claim (C) |
| 3 | Logs are **actually arriving** in Sentinel | Unknown for every source (U) |
| 4 | Logs are **retained and searchable** | Documented as a setting (C) |
| 5 | An **analytics rule** uses the logs | Only at template-family level (R) |
| 6 | The detection has been **tested** | Unknown for every source (U) |

## 4. Detection surface table

Evidence references are shown as *source § (class)*. Condition 6 (tested) is Unknown for every row and is not repeated in each cell.

### 4.1 Sentinel platform and Azure control plane

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Sentinel / Log Analytics workspace** `law-sentinel-prod` | Changes to analytics rules, connectors, diagnostic settings and retention appear as Azure Activity events. E2 §7 (I) | **Yes (documented)** for the control-plane events, via Azure Activity. E2 §7 (C) | 60 days in workspace. E1 §6 (C) | **Unknown — validation required.** No rule for logging or rule tampering is reported. E5 (R) |
| **Azure Activity Log** — all six subscriptions | Resource creation, change and deletion; role assignments; storage key listing; policy changes. E2 §7 (C) | **Yes (documented)** — Azure Activity connector enabled. E2 §7 (C); E5 (R). Arrival not verified (U) | 60 days in workspace. E1 §6, E2 §7 (C) | **Template (reported)** — built-in Azure Activity templates with default settings. E5 (R). Which templates: Unknown |
| **sub-sandbox** — 14 standing Owners, no Azure Policy initiative | Activity Log; resource logs only if someone configures them. E2 §1, §4 (C) | **Partial** — Activity Log only; resource diagnostics are not enforced. E2 §7 (C) | 60 days (Activity Log in workspace). E2 §7 (C) | **Template (reported)** for Activity events only. E5 (R) |
| **sub-nonprod** — Dev/UAT, incl. `sqldb-uat` with unmasked production account data and NI numbers | Activity Log, resource diagnostics, SQL audit. E2 §1, §3 (C) | **Partial** — Activity Log and resource diagnostics documented for landing-zone subscriptions; SQL audit on `sqldb-uat` **Unknown — validation required**. Defender for Cloud is Free tier. E2 §1, §7 (C) | 60 days for data in the workspace. E2 §7 (C) | **Template (reported)** for Activity events; nothing reported for UAT data access. E5 (R) |
| **Microsoft Defender for Cloud** | Security alerts for Azure resources. Standard tier on four subscriptions; Free tier on `sub-nonprod` and `sub-sandbox`. E2 §1 (C) | **Yes (documented)** — connector enabled. E2 §7 (C); E5 (R). Which Defender plans are on (servers, SQL, storage, containers): Unknown | 60 days in workspace. E1 §6 (C) | **Unknown — validation required.** Alerts arrive as alerts; whether incident-creation rules turn them into incidents is not documented. (I) |
| **Microsoft threat intelligence feed** | Indicators used to enrich and match other data. E2 §7 (C) | **Yes (documented)**. E2 §7 (C); E5 (R) | 60 days in workspace (I) | **Unknown — validation required.** TI only produces alerts if a matching rule exists. (I) |
| **Azure Automation** (`sub-management`) | Runbook execution, credential use. E2 §1 (C) | **Unknown — validation required.** Not listed in any logging table | Unknown | Unknown |
| **Azure DevOps pipelines and service principals** — one older pipeline still uses a client secret last rotated March 2024 | Pipeline runs, service connection use, service-principal sign-ins. E2 §5 (C) | **Unknown — validation required.** Azure DevOps audit is not mentioned; service-principal sign-in logs are not stated as part of the Entra connector | Unknown | Unknown |

### 4.2 Azure production workloads (`sub-prod`)

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Azure Front Door + WAF** (Prevention mode) | Blocked and allowed web requests, WAF rule matches. E1 §6, E2 §2 (C) | **Yes (documented)** — Azure WAF connector enabled. E1 §6, E2 §7 (C); E5 (R) | 60 days in workspace. E1 §6 (C) | **None reported.** Templates are reported only for Entra ID, Azure Activity and Azure Firewall. E5 (R) |
| **API Management** (Developer tier; mobile API) | Gateway requests, subscription-key use, rate-limit breaches. E2 §2 (C) | **Unknown — validation required.** Not listed in E1 §6 or E2 §7 | Unknown | Unknown |
| **App Service** — internet banking web front end (bypasses APIM) | HTTP request logs. E1 §6, E2 §2 (C) | **Yes (documented).** E1 §6 (C) | 60 days in workspace. E1 §6 (C) | **None reported.** E5 (R) |
| **AKS cluster** — 11 microservices incl. payments, onboarding, cards | Kubernetes API audit (secret reads, `exec`, role changes); control-plane and container logs. E1 §6, E2 §2 (C) | **Partial.** E1 §6 says control-plane and container logs are onboarded; E2 §7 and Marcus say the **AKS audit log is not enabled**. E1 §6, E2 §7 (C); E5 (R). Interpretation: some categories flow, the Kubernetes audit log does not (I) | **30 days** in workspace (differs from the 60-day default). E1 §6 (C) | **None reported**; audit-based detection **not possible** while the audit log is missing. E5 (R) |
| **Azure Functions** (batch and webhooks) | Execution and trigger logs. E2 §2 (C) | **Unknown — validation required** | Unknown | Unknown |
| **Azure SQL Managed Instance** `sqlmi-prod` — customer, account and transaction data (D1, D3, D5) | Database logins, queries, permission changes, affected row counts. E2 §3; E4 §1 (C) | **No.** Auditing is on at source but goes to a storage account; the Sentinel connector is not configured. E1 §6, E2 §7 (C); E5 (R) | **1 year** in immutable storage, **outside** Sentinel. E1 §6 (C). Workspace: none | **Not possible** in Sentinel. Indirect sight only: control-plane changes via Azure Activity; Defender for SQL alerts if that plan is on (Unknown) |
| **Storage** `stfinservedocs` — ID document images, NI numbers, statements (D2) | Blob reads, downloads, writes, deletes; SAS and account-key use. E2 §3; E4 §1 (C) | **No** — Storage diagnostics not enabled. E2 §7 (C); E5 (R). Account-key listing appears in Azure Activity (I) | Not collected, so none. Soft delete 30 days protects data, not logs. E2 §3 (C) | **Not possible** for data access. Partial: Azure Activity templates for control-plane events (R) |
| **Storage** `stfinservetfstate` — Terraform state (`sub-management`) | Blob reads and writes of infrastructure state. E2 §5 (C) | **No** — same Storage diagnostics gap. E2 §7 (C) | None (not collected) | **Not possible** for data access |
| **Key Vault** `kv-finserve-prod` — certificates, API keys, connection strings | Secret, key and certificate reads; access policy changes. E2 §3 (C) | **Unknown — validation required.** Not listed by name; covered only by the general "resource diagnostic settings" statement, which E2 §7 itself contradicts for Storage (I) | Unknown | Unknown |
| **Azure Cache for Redis** — customer session tokens | Connection and authentication events. E2 §3 (C) | **Unknown — validation required** | Unknown | Unknown |
| **Customer authentication and SCA** (mobile app / internet banking; OTP via Textway) | Customer logins, SCA challenges, failed OTP attempts, device changes. E4 §2 (C) | **Unknown — validation required.** No source for customer authentication events is documented; HTTP logs give only indirect sight (I) | Unknown | Unknown |

### 4.3 Network and connectivity

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Azure Firewall Premium** (hub) | Allowed and denied flows for all rules; inter-spoke and egress traffic. E1 §3, §6 (C) | **Yes (documented).** E1 §6, E2 §7 (C); E5 (R) | 60 days in workspace. E1 §6 (C) | **Template (reported)** — built-in Azure Firewall templates. E5 (R) |
| **VPN Gateway** (site-to-site and point-to-site, ~120 remote users) | Tunnel and user connection events. E1 §1, §4, §6 (C) | **Yes (documented).** E1 §6 (C) | 60 days in workspace. E1 §6 (C) | **None reported.** E5 (R) |
| **ExpressRoute gateway** (HQ and DC-SLO) | Circuit and route events. E1 §1, §2 (C) | **Unknown — validation required** | Unknown | Unknown |
| **Fortigate firewalls** (HQ and DC-SLO) | Flows and outbound web filtering. E1 §5, §6 (C) | **Yes (documented)** — via syslog. E1 §6 (C) | 60 days in workspace. E1 §6 (C) | **None reported.** E5 (R) |
| **Branch firewalls** (Manchester, Birmingham, Leeds) — flat LANs, local internet breakout | Flows, VPN tunnel events, local web traffic. E1 §1, §3, §5 (C) | **No** — local only. E1 §6 (C); E5 (R) | **14 days on device**, outside Sentinel. E1 §6 (C) | **Not possible** |
| **Cloudflare DNS and DDoS** | DNS changes, DDoS events. E1 §2 (C) | **Unknown — validation required.** Not mentioned in any logging table | Unknown | Unknown |

### 4.4 Identity and administrative access

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Microsoft Entra ID** -- ~470 accounts, 9 Conditional Access policies | Interactive sign-ins, risk events, directory and role changes. E3 §2, §7 (C) | **Yes (documented)** -- sign-in and audit logs. E2 §7, E3 §7 (C); E5 (R). E7 §1 lists both `SigninLogs` and `AADNonInteractiveUserSignInLogs` as collected (C), confirming that non-interactive sign-ins are included. Whether service-principal sign-ins are also selected: Unknown | 60 days in workspace; 30 days in Entra itself. E3 §7 (C) | **Template (reported)** -- built-in Entra ID templates. E5 (R) |
| **Break-glass accounts** (2; permanent Global Admin; excluded from MFA) | Sign-ins and changes to these accounts. E2 §4 (C) | **Yes (documented)** via Entra sign-in logs. E3 §7 (C) | 60 days in workspace. E3 §7 (C) | **Specific rule (documented)** — "sign-in alerting on these accounts is configured in Sentinel". E2 §4 (C). Tested: Unknown |
| **`CA-Exclusions-Service` group** — break-glass, 3 service accounts, FinRecon shared mailbox (IMAP basic auth) | Sign-ins that bypass the MFA, legacy-auth block and country block policies. E3 §2 (C) | **Yes (documented)** via Entra sign-in logs, if those sign-in types are collected. E3 §7 (C); (U) | 60 days in workspace. E3 §7 (C) | **Unknown — validation required.** Only the break-glass rule is documented |
| **Domain controllers** x2 -- `finserve.local`; 6 Domain Admins who also use these accounts day to day | Windows Security events: logons, group changes, Kerberos activity. E1 §6; E3 §2 (C) | **Yes (documented)** via Azure Monitor Agent. E1 §6 (C); E7 §2: hosts `DC-01` and `DC-02` using `dcr-security-events-common` (C). The data collection rule uses the **Common** event set, not All (E7 §2, §5). E7 §5 notes that "several event IDs relevant to credential access are outside it" (C). Event IDs 4728, 4732, 4756 (group changes) are in the Common set; some Kerberos and credential-access events (4768, 4769, 4771) are not (I) | 60 days in workspace. E1 §6 (C) | **Unknown -- validation required.** No AD-specific rule reported. E5 (R) |
| **Entra Connect server** (`sub-identity`; password hash sync) | Windows Security events; directory synchronisation activity. E3 §2 (C) | **Yes (documented)** via Azure Monitor Agent. E7 §2: `ENTRACONNECT-01` is one of four hosts forwarding Windows Security Events, using `dcr-security-events-common` (C). Not listed in E1 §6 or E2 §7 (discrepancy resolved by E7). Event scope: **Common** event set, not All (E7 §5). | 60 days in workspace. E7 §4 (C) | **Unknown -- validation required.** No rule reported for synchronisation activity. E5 (R) |
| **JUMP-01** -- all administrative access to production; RDP from an IP allowlist | Windows Security events: RDP logons, privilege use. E1 §4, §6 (C) | **Yes (documented)** via Azure Monitor Agent. E1 §6 (C); E7 §2: `JUMP-01` using `dcr-security-events-common` (C). **Common** event set (E7 §2). Event ID 4624 (logon, including RDP type 10) is in the Common set; DET-08 should work for this host (I) | 60 days in workspace. E1 §6 (C) | **Unknown -- validation required.** E5 (R) |
| **Azure RBAC** — standing Owner/Contributor; PIM licensed but not configured; access via Entra groups | Role assignment changes (Azure Activity); group membership changes (Entra audit). E2 §4 (C) | **Yes (documented)** via Azure Activity and Entra audit logs. E2 §7 (C) | 60 days in workspace. E2 §7 (C) | **Template (reported)** for Azure Activity and Entra families. E5 (R). Coverage of group-based privilege changes: Unknown |

### 4.5 Microsoft 365 and endpoints

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Exchange Online, SharePoint, OneDrive, Teams** | Mailbox access, inbox rules, file access and sharing, guest activity. E3 §3, §4 (C) | **Yes (documented)** — Microsoft 365 connector. E2 §7 (C); E5 (R). It is unlikely to carry the full Unified Audit Log (I) | Workspace 60 days. Unified Audit Log in Purview: **180 days (E5, 120 users) / 90 days (E3/F3, 330 users)**. E3 §7 (C) | **None reported** for M365 activity. E5 (R) |
| **Defender for Office 365** | Phishing, malware, impersonation alerts. E3 §1, §3 (C) | **Partial.** E7 §1 lists the Microsoft Defender XDR connector as "Connected" with tables `SecurityAlert` and `SecurityIncident` (C). This partly resolves discrepancy X3: the connector exists, but carries **alerts only**, not raw events. Whether email-specific alerts (phishing, impersonation) reach it: confirm in workspace | 60 days in workspace for alerts. E7 §1 (C) | Alerts only, via the XDR connector. No custom detection for email threats (R) |
| **Defender for Endpoint** -- 355 corporate Windows 11 laptops | Process, network and logon events; endpoint alerts; ASR events (7 of 16 rules in Audit mode). E3 §6 (C) | **Partial.** E7 §1 lists the Defender XDR connector as "Connected" (C), resolving the E2 §7 / E5 omission. Tables `SecurityAlert` and `SecurityIncident` are in the workspace. **Raw endpoint events** (process, network, logon) are **not** carried by the connector at this scope; they remain in the Defender portal (I). Whether advanced hunting tables (`DeviceEvents` etc.) are forwarded: confirm in workspace | Raw events **30 days** in Defender portal; alerts **180 days**. Alert copies: 60 days in workspace. E3 §7 (C); E7 §1 (C) | Alerts only, via the XDR connector. No custom endpoint detection in Sentinel (R) |
| **macOS (22), corporate iOS/Android (95), BYOD (~210)** | Device events; BYOD has app protection only, with compliance policy in report-only. E3 §6 (C) | **Unknown — validation required.** Defender for Endpoint is documented for Windows only | Unknown | Unknown |
| **Microsoft Intune** | Device enrolment, policy and compliance changes. E3 §6 (C) | **No** — "Intune only, not forwarded". E3 §7 (C) | **1 year** in Intune, outside Sentinel. E3 §7 (C) | **Not possible** |
| **Microsoft Purview DLP** — NI number, card number and credential policies | DLP policy matches and incidents. E3 §5 (C) | **No** — Purview and email to `dlp-alerts@`. E3 §7 (C) | **180 days** in Purview. E3 §7 (C) | **Not possible** in Sentinel |
| **File services** (shared-services spoke; dev subnet access under CHG-2025-0132) | File access, share permission changes. E1 §2, §3.1 (C) | **Unknown — validation required** | Unknown | Unknown |

### 4.6 Legacy estate — Slough data centre (DC-SLO)

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **DC-SLO SFTP server** — nightly settlement file (D3) to Meridian Trust; static password unchanged since 2019 | SSH/SFTP logins, file transfers, scheduled task runs. E1 §6; E4 §4 (C) | **No** — local syslog only. E1 §6 (C) | **30 days on device**, outside Sentinel. E1 §6 (C) | **Not possible.** Indirect sight via DC-SLO Fortigate flows (I) |
| **FinRecon** — reconciliation desktop tool; reads a shared mailbox over IMAP basic auth; vendor support from Bengaluru | Application logs; mailbox sign-ins (in Entra); remote support sessions. E3 §2; E4 §2–§5 (C) | **Partial** — only the mailbox sign-ins, via Entra. Application and remote-session logs: **Unknown — validation required** | 60 days for Entra data. E3 §7 (C) | **Unknown — validation required** |
| **Other DC-SLO workloads** (11 workloads remain in total) | Unknown — the workloads are not listed. E1 §8 (C) | **Unknown — validation required** | Unknown | Unknown |

### 4.7 Third parties

| System | Security-Relevant Telemetry | Reaches Sentinel? | Retention | Analytics Rule Coverage |
|---|---|---|---|---|
| **Corebridge** — core banking and card processing (D1, D3, D4) | Application, administrator and transaction logs. E1 §6; E4 §3 (C) | **No** — held by Corebridge; "accessible by ticket". E1 §6 (C) | "Per contract" — period not documented. **Unknown — validation required** | **Not possible** |
| **Textway** — SMS one-time passcodes and alerts | Message delivery and OTP events. E4 §2, §3 (C) | **No** — no telemetry to FinServe documented. E4 §3 (C) | Unknown | **Not possible** |
| **IDVerify** — identity verification API | API calls and verification results. E4 §2, §3 (C) | **No** documented telemetry. Outbound calls may be visible in App Service or AKS logs (I) | Unknown | **Not possible** |
| **Meridian Trust** — settlement counterparty SFTP endpoint | Login and file receipt at their end. E4 §4 (C) | **No.** E4 §3 (C) | Unknown | **Not possible** |
| **Solvex** — FinRecon vendor remote support from Bengaluru | Remote session logs. E4 §5 (C) | **Unknown — validation required.** How Solvex connects is not documented | Unknown | Unknown |

## 5. Practical visibility limitations

These are the most important consequences of the table. Each states what the SOC would and would not see. None has been tested.

1. **Customer database (Azure SQL MI).** An attacker using a stolen database credential could read or extract customer and transaction records without generating database-level activity in Sentinel. Five AKS services authenticate with connection strings stored as Kubernetes secrets (E2 §2), and a standing firewall exception lets UAT reach `sqlmi-prod` on port 1433 (E1 §3.1). Azure Activity would show changes to the server itself, not the queries. The 1-year audit trail in storage means the activity could be investigated afterwards, but nobody would be alerted while it happens.
2. **Identity documents (`stfinservedocs`).** Bulk download of passport and licence images and NI numbers would not appear in Sentinel. If the attacker first lists the storage account keys, that control-plane action is recorded in Azure Activity (I); a download using an existing SAS token or application identity would leave no Sentinel trace.
3. **Inside the AKS cluster.** Reading Kubernetes secrets, running `exec` in a payments pod or changing cluster roles would not be recorded in Sentinel, because the audit log is not collected. Container logs may show side effects, such as application errors, and are only kept for 30 days.
4. **Settlement path in Slough.** Use of the static SFTP credential, or tampering with the nightly file, would be recorded only on the server and kept for 30 days. The DC-SLO Fortigate might show unusual connections, but not the logins or file contents. The business process notices a failure only when the 07:00 reconciliation report is missing or Meridian Trust telephones (E6).
5. **Branches.** Lateral movement across the flat branch LANs, or malicious browsing over the local internet breakout, would not reach Sentinel. Partial sight is likely through Defender for Endpoint on the corporate laptops branch staff use (E3 §6; E6) (I).
6. **Core banking at Corebridge.** Administrator misuse or fraud inside Corebridge would be invisible to the SOC. Investigation would depend on a ticket with an undocumented turnaround.
7. **Data that arrives but is not watched.** WAF, App Service, VPN Gateway, Fortigate, Microsoft 365 activity and Windows Security events are reported or documented as reaching the workspace, but no analytics rules are reported for them. That data supports an investigation, but nothing in it is likely to raise an alert.
8. **Endpoints beyond corporate Windows.** Visibility of macOS, mobile and BYOD devices is not documented; the BYOD compliance policy has been in report-only mode since February 2025 (E3 §6).

## 6. Assumptions and validation requirements

### 6.1 Assumptions

| # | Assumption |
|---|---|
| A1 | The architecture documents describe intended configuration at their review dates (August–November 2025). They are treated as claims, not observed state. |
| A2 | Marcus Ifill's connector list, rule description, alert statistics and retention position are accurate as reported for the 30 days before the briefing. |
| A3 | Workspace retention of 60 days applies to every workspace table unless a document states otherwise (AKS: 30 days, E1 §6). Per-table settings have not been checked. |
| A4 | No queries have been run, no portal has been viewed and no detection has been tested. |
| A5 | Where a document says "Yes" or "onboarded", only collection (condition 2) is accepted. Arrival (condition 3) is treated as Unknown. |

### 6.2 Discrepancies to resolve

| # | Discrepancy | Evidence | Class |
|---|---|---|---|
| X1 | AKS: "control plane + container logs → Log Analytics, onboarded: Yes" versus "AKS audit log: not enabled". | E1 §6 vs E2 §7; E5 | Conflict in documentation |
| X2 | "All subscriptions send resource diagnostic settings" versus "Storage diagnostics not enabled". | E2 §7 | Internal contradiction |
| X3 | Defender for Office 365 and Defender for Endpoint data are documented as reaching Sentinel, but no Defender XDR connector appears in the E2 §7 or Marcus lists. **Partly resolved:** E7 §1 lists Microsoft Defender XDR as "Connected" with `SecurityAlert` and `SecurityIncident` tables. The connector exists, but the scope of what it carries (alerts only, or also raw advanced hunting tables) needs validation. | E3 §7 vs E2 §7; E5; **resolved by** E7 §1 | Partly resolved |
| X4 | One-year retention described as "rejected" by Marcus, and as "priced … and deferred" in the network document. | E5 vs E1 §6 | Reported vs documented |

### 6.3 How to validate with read-only access

With Microsoft Sentinel Reader and Log Analytics Reader on `law-sentinel-prod`, each Unknown can be resolved without changing anything:

| Check | Where | Read-only method |
|---|---|---|
| Is each connector actually sending data? | Microsoft Sentinel → Configuration → Data connectors | Check status and "last data received"; confirm with the query below |
| Which tables receive data, and how much? | Log Analytics → Logs | `Usage` query below |
| What is the retention per table? | Log Analytics workspace → Settings → Tables | Read the retention column for each table |
| Which analytics rules exist and are enabled? | Microsoft Sentinel → Configuration → Analytics → Active rules | Record name, data source, status, last modified; ask Marcus for an export |
| Which diagnostic settings exist on a resource? | Resource → Monitoring → Diagnostic settings | Record categories and destination (`sqlmi-prod`, `stfinservedocs`, AKS, Key Vault) |
| Which Windows events are collected? | Azure Monitor → Data Collection Rules | Read the event filter in the rule for JUMP-01 and the DCs |

Illustrative read-only query, not yet run, showing which tables have received data in the last 30 days:

```kql
// Which data types (tables) have received data in the last 30 days, and how much?
// Read-only: Usage is a standard Log Analytics table. Run over a short range first.
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize IngestedGB = round(sum(Quantity) / 1024, 2), LastRecord = max(TimeGenerated) by DataType
| sort by IngestedGB desc
```

Expected use: compare the `DataType` list with this map. A table that should exist but is missing (for example `SecurityEvent` for the DCs) or that stopped receiving data days ago is an ingestion gap. `Quantity` is reported in MB.

The questions that would resolve the Unknowns are listed, in priority order, in `Coverage-Gaps.md` Section 9.

## 7. Brief SOC observations

- **The detection surface is strongest at the Azure and identity control plane** (Azure Activity, Entra ID, Azure Firewall), which is where the reported templates are focused.
- **It is weakest where the bank's most sensitive data lives.** The customer database, the ID document store and the inside of the AKS cluster all produce logs that do not reach Sentinel.
- **Some of the riskiest paths sit outside Azure** (the Slough settlement server, branches, Corebridge) and depend on local logs or supplier tickets.
- **Collected does not mean watched.** At least six sources reportedly arrive in the workspace with no analytics rule reported for them.
- **Two of the four custom rules are non-functional or broken.** CUST-03 ("Database mass export") queries `SQLSecurityAuditEvents`, a table that does not exist in the workspace because the SQL audit connector has never been enabled (E7 §1; E8 §2). It has generated zero alerts since deployment (E9 §2). CUST-02 ("Privileged role assignment outside change window") contains inverted logic: its KQL `between` clause keeps events **inside** 09:00-17:00 rather than outside it, meaning it alerts on legitimate daytime changes and misses out-of-hours ones (E8 §2). Marcus noted he had not reviewed it (E5). Both are effectively false protection.
- **Retention varies from 14 days to 1 year** depending on where the data lives, and the longest periods (SQL audit, Intune) are outside Sentinel.
- **Everything here is provisional** until arrival (condition 3) and rule behaviour (conditions 5 and 6) are checked in the workspace.
