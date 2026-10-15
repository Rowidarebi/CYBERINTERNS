# Coverage Gap Assessment

**Project Sentinel · Inject 03 **

| Item | Detail |
|---|---|
| Client | FinServe Digital Bank Ltd |
| Workstream | Security Operations (SOC) |
| Deliverable | `06-DELIVERABLES/SOC/Coverage-Gaps.md` |
| Companion documents | `Detection-Surface.md`, `Detection-Backlog.md` |
| Date | 11 October 2026 |
| Prepared by | SOC Team |
| Status | **Provisional.** Priorities are based on documents and client-reported information. They may change once the questions in Section 9 are answered and the workspace can be inspected. |

## 1. Purpose

This assessment takes the blind spots identified in `Detection-Surface.md` and asks two questions for each: **what could an attacker do there without the SOC noticing, and how much would it hurt FinServe?** The gaps are then ranked by consequence so the bank can decide what to fix first.

## 2. Evidence base

Evidence references (E1–E6) and classifications are the same as in `Detection-Surface.md` Section 2 and 3:

| Ref | Source |
|---|---|
| E1 | `02-ARCHITECTURE/01-Network-Diagram.md` |
| E2 | `02-ARCHITECTURE/02-Azure-Architecture.md` |
| E3 | `02-ARCHITECTURE/03-M365-Architecture.md` |
| E4 | `02-ARCHITECTURE/04-Data-Flow.md` |
| E5 | Inject 03 briefing from Marcus Ifill, Security Operations Manager (reported) |
| E6 | `01-CLIENT/01-Company-Profile.md`, `02-Organisation-Chart.md`, `03-Business-Processes.md`, `04-Stakeholders.md` |
| E7 | `04-SOC/Logs/Log-Source-Inventory.md` |
| E8 | `04-SOC/Alerts/Analytics-Rules.md` |
| E9 | `04-SOC/Alerts/Alert-Summary-30-Days.md` |

**Confirmed (C)** = stated in the documentation · **Reported (R)** = stated by the client, not verified · **Inferred (I)** = reasoned interpretation · **Unknown (U)** = validation required.

## 3. Prioritisation method

Each gap is assessed on three factors. **How easy the gap is to close does not affect its priority**; difficulty is recorded separately.

| Factor | Question asked | Higher when… |
|---|---|---|
| Impact | What data, service or privilege is exposed? | Restricted customer data (D2, D3), credentials (D7), privileged access, or an important business service / settlement process is involved (E4 §1) |
| Attacker consequence | What could an attacker achieve unobserved? | Data theft, unauthorised changes to money or records, lateral movement, ransomware, or removal of evidence |
| Compensating visibility | Would any other log source give the SOC partial sight? | No other source exists, or it would only show the activity after the damage is done |

| Priority | Definition |
|---|---|
| **Critical** | High impact and high consequence with little or no compensating visibility. Raise with the CISO now; do not wait for the board report. |
| **High** | High impact with partial compensating visibility, or a broad gap affecting many sources. Address in the next 30 days. |
| **Medium** | Moderate impact, or meaningful compensating visibility exists. Plan into the next quarter. |
| **Low** | Limited impact; track. |
| **Provisional** | Cannot be rated until an Unknown is resolved. |

Implementation difficulty is rated **Low / Medium / High** from the documented architecture only; cost and effort have not been estimated with FinServe.

## 4. Gap summary

| ID | Gap | Affected system | Priority | Difficulty | Evidence status |
|---|---|---|---|---|---|
| G1 | Database audit not in Sentinel | Azure SQL MI `sqlmi-prod` | **Critical** | Low–Medium | Confirmed + Reported |
| G2 | No data-access logging for ID documents | Storage `stfinservedocs` (and `stfinservetfstate`) | **Critical** | Medium | Confirmed + Reported |
| G3 | Settlement server and Slough workloads outside Sentinel | DC-SLO SFTP server, FinRecon, other DC-SLO workloads | **High** | Medium | Confirmed + Unknown |
| G4 | No Kubernetes audit log | AKS production cluster | **High** | Low–Medium | Confirmed + Reported (conflict X1) |
| G5 | Data collected but no analytics rule watching it | WAF, App Service, VPN, Fortigate, M365, DCs, JUMP-01, CA exclusions | **High** | Medium | Reported + Inferred |
| G6 | No visibility into third-party systems | Corebridge, Textway, IDVerify, Meridian Trust, Solvex | **High** | High | Confirmed |
| G7 | Sandbox and non-production blind spots | `sub-sandbox`, `sub-nonprod`, `sqldb-uat` | **Medium–High** | Medium | Confirmed |
| G8 | Branch firewall logs local only | Branch firewalls (MAN, BIR, LEE) | **Medium** | Medium | Confirmed + Reported |
| G9 | Endpoint and M365 data outside Sentinel | Intune, Purview DLP, Unified Audit Log, Defender XDR, non-Windows devices | **Medium** | Low–Medium | Confirmed + Unknown (conflict X3) |
| G10 | Coverage not documented | Entra Connect, Key Vault, APIM, Functions, Redis, Azure DevOps, Automation, file services, ExpressRoute, Cloudflare, customer authentication | **Provisional** (Entra Connect, Key Vault and customer authentication likely High) | Unknown | Unknown |

## 5. Gap details

### G1 — Azure SQL MI audit not in Sentinel

| Field | Detail |
|---|---|
| Gap ID | G1 |
| Affected system | Azure SQL Managed Instance `sqlmi-prod` — customer identity, account and transaction metadata (D1, D3, D5) for ~180,000 customers |
| Evidence source | E1 §6: "Azure SQL MI audit → Storage account, immutable, 1 year — Partial — audit on, Sentinel connector not configured" (C). E2 §7: Azure SQL audit "Not enabled" as a connector (C). E5: Azure SQL audit disabled/missing (R). E2 §2: five AKS services use connection strings stored as Kubernetes secrets (C). E1 §3.1: CHG-2024-0881 lets UAT reach `sqlmi-prod` on 1433 (C). E6 (`04-Stakeholders` §4): Marcus has asked twice for the connector to be enabled (C) |
| Visibility gap | Database auditing exists at source but is written only to a storage account. Sentinel receives no database logins, queries or permission changes, so no analytics rule can use them. |
| Attacker activity that could go unobserved | Using a stolen connection string or SQL login to run large `SELECT` queries against customer tables; creating a new database user; granting permissions; changing records; querying from the UAT path. |
| Business and security consequences | Theft of Restricted customer and transaction data; UK GDPR breach with 72-hour ICO notification requiring scope that the SOC could not quickly establish; regulatory and reputational damage during the funding round (E6). Investigation is still possible afterwards from the 1-year audit in storage, but nobody is alerted while it happens. |
| What closes the gap | Send SQL MI security audit events to `law-sentinel-prod` (diagnostic setting for the audit category) while keeping the immutable storage copy. Agree which audit action groups are needed to control volume. Then build detection DET-01 (`Detection-Backlog.md`). |
| Implementation difficulty | **Low–Medium.** A configuration change plus an ingestion cost estimate; audit is already on at source. |
| Priority and rationale | **Critical.** Highest-value data store; a realistic credential path exists (E2 §2); no compensating detection in Sentinel. Defender for SQL might give partial alerting, but whether it is enabled is Unknown. |
| Dependencies and validation | Confirm current audit action groups and the destination storage account (Q7). Confirm whether the Defender for SQL plan is enabled (Q6). Ingestion volume and cost estimate. Authorisation from Marcus and the CISO before any change. |

### G2 — No data-access logging for the identity document store

| Field | Detail |
|---|---|
| Gap ID | G2 |
| Affected system | Storage account `stfinservedocs` — passport and driving licence images, NI numbers, statements (D2, Restricted, ~180,000 subjects). Secondary: `stfinservetfstate` (Terraform state) |
| Evidence source | E2 §3: document store contents (C). E4 §1: D2 classified Restricted (C). E2 §7: "Not enabled: … Storage diagnostics" (C). E5: Azure Storage diagnostics disabled/missing (R). E2 §5: Terraform state account (C) |
| Visibility gap | Blob read, download, write and delete operations are not logged to Sentinel. Only control-plane actions (for example listing the account keys) reach the workspace, through Azure Activity (I). |
| Attacker activity that could go unobserved | Bulk download of ID document images using a SAS token, an application identity or an account key obtained earlier; deletion or overwriting of documents; reading Terraform state, which commonly contains resource secrets (I). |
| Business and security consequences | Loss of identity documents enables identity fraud against customers. This is the most damaging category of personal data breach for a retail bank and carries ICO notification and customer communication obligations. Without access logs, FinServe could not say which customers were affected. |
| What closes the gap | Enable blob diagnostic logging (read, write, delete) on `stfinservedocs` and `stfinservetfstate` to the workspace. Assess volume first; consider a workspace transformation to keep only the fields needed. Then build DET-02. |
| Implementation difficulty | **Medium.** A simple setting, but read logging on a busy document store may be high volume and needs a cost decision. |
| Priority and rationale | **Critical.** Restricted data at full customer scale; the only partial visibility (key listing in Azure Activity) does not cover the most likely access methods. |
| Dependencies and validation | Confirm whether Defender for Storage is enabled (Q6). Confirm current diagnostic settings on both accounts (Q11). Volume estimate. Authorisation before change. |

### G3 — Settlement server and Slough workloads outside Sentinel

| Field | Detail |
|---|---|
| Gap ID | G3 |
| Affected system | DC-SLO SFTP server (nightly settlement extract to Meridian Trust, D3); FinRecon reconciliation tool; the other DC-SLO workloads (11 in total) |
| Evidence source | E1 §6: "DC-SLO SFTP server → Local syslog, 30 days on device — No" (C). E4 §4: delivery script uses a static password unchanged since 2019, shown in plain text in the configuration extract (C). E4 §5: Solvex remote support from Bengaluru with sight of D3 (C). E1 §8: 11 DC-SLO workloads remain (C). E6 (`03-Business-Processes` §4): failure noticed only when the 07:00 report is missing or Meridian Trust telephones (C). E6 (`02-Organisation-Chart` §6): Head of Infrastructure, who holds the Slough knowledge, is leaving (C) |
| Visibility gap | Logins and file activity on the settlement server stay on the server for 30 days. The other Slough workloads are not identified, so their logging cannot be assessed. Only DC-SLO Fortigate flows reach Sentinel. |
| Attacker activity that could go unobserved | Logging in to the SFTP server; altering the settlement file before delivery; reusing the static Meridian Trust credential; misuse of vendor remote-support access; persistence on an unidentified legacy host. |
| Business and security consequences | Incorrect or fraudulent settlement data sent to a counterparty; financial loss and reconciliation failure; disclosure of transaction data; an investigation hampered by 30-day local logs. Losing the person who knows Slough best makes later reconstruction harder. |
| What closes the gap | Inventory the remaining DC-SLO workloads. Forward the SFTP server's authentication and transfer logs to the workspace (a syslog path already exists for the DC-SLO Fortigate, E1 §6). Consider file integrity monitoring on the settlement file. Then build DET-06. Separately: the plain-text credential shown in E4 §4 should be reported to the CISO now so she can decide whether to rotate it — this is outside the SOC's authority to change. |
| Implementation difficulty | **Medium.** Depends on the server's operating system and logging ability (Unknown). |
| Priority and rationale | **High.** Settlement data and a long-lived credential on a process that runs unattended overnight. Partial network visibility via Fortigate keeps it below Critical, but the rating may rise once the other Slough workloads are known. |
| Dependencies and validation | Session with Tobi Okonkwo before he leaves. Server OS and syslog capability (Q8). Whether the credential is still valid (CISO decision). |

### G4 — No Kubernetes audit log for the production cluster

| Field | Detail |
|---|---|
| Gap ID | G4 |
| Affected system | AKS 1.29 production cluster — 11 microservices including payments, accounts, cards, onboarding and limits |
| Evidence source | E2 §2: services and secrets usage (C). E2 §7: "Not enabled: … AKS audit log" (C). E1 §6: "AKS control plane + container logs → Log Analytics, 30 days, Yes" (C). E5: AKS audit logs disabled/missing (R). Interpretation: some AKS log categories flow, the audit category does not (I) |
| Visibility gap | Actions taken through the Kubernetes API — who read a secret, who ran a command inside a pod, who changed a role binding — are not in Sentinel. Container logs that are collected are kept only 30 days. |
| Attacker activity that could go unobserved | Reading the Kubernetes secrets that hold SQL connection strings (leading to G1); `kubectl exec` into the payments service; deploying a malicious container; granting cluster-admin to a new identity. |
| Business and security consequences | Compromise of the systems that run payments and onboarding (important business services), and a direct path to customer data. Payment fraud or service disruption. |
| What closes the gap | Enable the AKS audit diagnostic category to the workspace. Note: the lower-volume `kube-audit-admin` category excludes read (`get`/`list`) events, so it would **not** show secret reads; full `kube-audit` is needed for that (I). Decide with Marcus based on volume. Then build DET-07. |
| Implementation difficulty | **Low–Medium.** A diagnostic setting change; the main decision is volume and cost. |
| Priority and rationale | **High.** Critical services and a credential path to G1. Partial indirect visibility from container and control-plane logs keeps it below Critical. |
| Dependencies and validation | Confirm exactly which AKS diagnostic categories are on (Q5, discrepancy X1). Volume estimate. Authorisation. |

### G5 — Data collected but no analytics rule watching it

| Field | Detail |
|---|---|
| Gap ID | G5 |
| Affected system | Front Door/WAF, App Service, VPN Gateway, Fortigate, Microsoft 365 activity, domain controllers, JUMP-01, `CA-Exclusions-Service` accounts, Defender for Cloud alerts |
| Evidence source | E5: rules are built-in templates for Entra ID, Azure Activity and Azure Firewall, with default configuration, plus four custom KQL rules, two of uncertain function (R). E1 §6: "There is no formal detection engineering backlog" (C). E1 §6, E2 §7, E3 §7: the sources above are documented as reaching the workspace (C). E6 (`02-Organisation-Chart` §4): no detection engineering role (C). E8 §2: full KQL for all four custom rules (C). E9 §2: alert counts by rule (C) |
| Visibility gap | Several sources reportedly arrive in the workspace but no rule is reported for them. Default templates are not tuned to FinServe's environment. Of the four custom rules, two are non-functional: **CUST-03** ("Database mass export") queries `SQLSecurityAuditEvents`, which does not exist in the workspace because the SQL audit connector was never enabled (E7 §1; E8 §2). It has produced zero alerts since deployment (E9 §2). Marcus took the silence as good news; it was the absence of data (E5). **CUST-02** ("Privileged role assignment outside change window") has inverted logic: the `between` clause in its KQL retains events **inside** the 09:00-17:00 window, not outside it, so it alerts on legitimate daytime changes and passes out-of-hours assignments in silence (E8 §2). It produced 9 incidents in 30 days, all closed as informational (E9 §2), consistent with catching normal working-hours activity. Marcus noted he had not reviewed the rule (E5). Two of FinServe's four custom detections have provided no real protection since they were deployed. |
| Attacker activity that could go unobserved | Web attacks that get past or around the WAF; misuse of VPN accounts; malicious inbox rules in finance mailboxes; Domain Admins group changes; RDP logons to JUMP-01 by unexpected accounts; sign-ins by MFA-excluded service accounts from unusual locations. |
| Business and security consequences | The bank pays to collect data that does not protect it. Attacks are recorded but only found later, if someone searches. This is the cheapest gap to close because the telemetry is already there. |
| What closes the gap | Disable or fix the two broken custom rules (CUST-02 and CUST-03) immediately, since they give a false impression of coverage. Obtain the full rule inventory; review the remaining custom and built-in rules; map existing rules to the data sources and to MITRE ATT&CK; adopt the prioritised `Detection-Backlog.md` (Category A detections first, with DET-05 effectively replacing CUST-02). |
| Implementation difficulty | **Medium.** No new data needed, but it requires analyst time the two-person SOC does not have (E6). |
| Priority and rationale | **High.** It affects many sources at once, including privileged access paths (JUMP-01, DCs, CA exclusions). Rated below G1/G2 because some indirect visibility exists through Entra and Azure Activity templates. |
| Dependencies and validation | Rule inventory and the four custom rules (Q2). Confirmation that the data is actually arriving (Q1, Q3). Windows event scope for DCs and JUMP-01: E7 §2 confirms the data collection rule uses the **Common** event set, and E7 §5 notes that "several event IDs relevant to credential access are outside it." Group-change events (4728, 4732, 4756) are in Common; some Kerberos and credential events are not. Q10 is partly answered by E7 but should still be confirmed in the DCR. |

### G6 — No visibility into third-party systems

| Field | Detail |
|---|---|
| Gap ID | G6 |
| Affected system | Corebridge (core banking and cards), Textway (SMS one-time passcodes), IDVerify, Meridian Trust, Solvex |
| Evidence source | E1 §6: Corebridge application logs "Held by Corebridge, per contract — accessible by ticket" (C). E4 §3: Corebridge holds D1, D3, D4; Textway receives phone numbers and amounts; no DPA with Textway (C). E4 §5: Solvex remote support from Bengaluru (C) |
| Visibility gap | FinServe's core banking, card processing and SCA delivery run on supplier systems. The SOC has no live security telemetry from any of them and depends on a ticket for Corebridge logs. |
| Attacker activity that could go unobserved | Misuse of administrator access at Corebridge; fraudulent postings; interception or redirection of one-time passcodes at the SMS supplier; compromise of the FinRecon vendor's remote support path. |
| Business and security consequences | Fraud and customer harm in the services that matter most (payments, card payments, account access). Delayed investigation while waiting for supplier logs, which matters for the 72-hour ICO notification window and for operational resilience reporting. |
| What closes the gap | Agree with Corebridge which security logs FinServe can receive, in what format, how quickly and for how long; agree security-event notification terms with Corebridge and Textway; document and log how Solvex connects. These are contractual and supplier-management actions, shared with the GRC track. |
| Implementation difficulty | **High.** Depends on supplier contracts and cooperation. |
| Priority and rationale | **High.** Very high impact, but partly outside FinServe's direct control; some indirect visibility exists (Azure Firewall flows to Corebridge, App Service/AKS logs of API calls) (I). |
| Dependencies and validation | Corebridge contract terms (Q14). How Solvex connects (Q8). GRC supplier register comparison. |

### G7 — Sandbox and non-production blind spots

| Field | Detail |
|---|---|
| Gap ID | G7 |
| Affected system | `sub-sandbox` (14 standing Owners, no policy); `sub-nonprod` including `sqldb-uat` |
| Evidence source | E2 §1: sandbox excluded from policy by design; non-prod and sandbox on Defender for Cloud Free tier (C). E2 §4: 14 Owners on sandbox, 21 Contributors on non-prod (C). E2 §7: sandbox sends Activity Log only (C). E2 §3: UAT refreshed nightly from production with account numbers, balances, transaction history and NI numbers unmasked (C). E1 §3.1: CHG-2024-0881 UAT to `sqlmi-prod`; CHG-2025-0132 dev to file server (C) |
| Visibility gap | Resources created in the sandbox produce no resource logs in Sentinel. Non-production has no Defender for Cloud threat protection. Whether `sqldb-uat` is audited at all is Unknown. |
| Attacker activity that could go unobserved | Copying or querying real customer data in UAT; using UAT as a stepping stone to production SQL; standing up unmonitored resources in the sandbox (for example a public endpoint or a VM used for staging). |
| Business and security consequences | A breach of production customer data that happens in a non-production environment is still a breach. Weaker monitoring there makes it the easier target. |
| What closes the gap | Treat `sqldb-uat` as a production-class data store for monitoring (audit to the workspace); extend diagnostic settings and Defender plans to non-prod; alert on high-risk resource types created in the sandbox. Reducing the production data in UAT is a GRC/data-protection recommendation. |
| Implementation difficulty | **Medium.** |
| Priority and rationale | **Medium–High.** Restricted data at full scale but behind more access steps than production; Activity Log gives partial sight. |
| Dependencies and validation | Is SQL auditing enabled on `sqldb-uat` (Q7)? Diagnostic settings in non-prod (Q11). |

### G8 — Branch firewall logs kept locally only

| Field | Detail |
|---|---|
| Gap ID | G8 |
| Affected system | Branch firewalls at Manchester, Birmingham and Leeds (~140 users); flat branch LANs |
| Evidence source | E1 §6: "Branch firewalls → Local only, 14 days on device — No" (C). E1 §3: branch LANs are flat, no VLAN segmentation (C). E1 §5: branches use local internet breakout for browsing (C). E5: branch firewalls a known gap (R). E3 §6 and E6 (`02-Organisation-Chart` §7): branch staff use corporate laptops, which run Defender for Endpoint if Windows (C/I) |
| Visibility gap | Branch traffic, including all general internet browsing, never passes through Azure Firewall or the HQ Fortigates, and the branch firewall logs do not reach Sentinel. |
| Attacker activity that could go unobserved | Malware downloads over the local breakout; command-and-control traffic; lateral movement between devices on the flat LAN; ransomware spreading inside a branch. |
| Business and security consequences | Disruption to branch services for ~4,100 regular customers (E6); a foothold that could later reach Azure over the site-to-site VPN. Branch staff have no administrative access to Azure (E1 §4), which limits the impact. |
| What closes the gap | Confirm the branch firewalls can export syslog; forward them to the existing collector over the VPN, or at least forward security events (threat, VPN, admin login) to limit bandwidth. |
| Implementation difficulty | **Medium.** Depends on device capability and branch bandwidth. |
| Priority and rationale | **Medium.** Significant compensating visibility is likely from Defender for Endpoint on corporate laptops (I), and branches have no Azure admin access. |
| Dependencies and validation | Firewall model and syslog capability (Q9). Confirm Defender for Endpoint coverage of branch devices (Q4). |

### G9 — Endpoint and Microsoft 365 data outside Sentinel

| Field | Detail |
|---|---|
| Gap ID | G9 |
| Affected system | Intune, Purview DLP, the full Unified Audit Log, Defender for Endpoint and Defender for Office 365 data, macOS / mobile / BYOD devices |
| Evidence source | E3 §7: Intune audit "Intune only, not forwarded"; DLP incidents in Purview and email; Defender for Endpoint "Defender portal + Sentinel", 30 days raw, 180 days alerts; UAL 180/90 days (C). E7 §1: Microsoft Defender XDR connector listed as "Connected" with tables `SecurityAlert` and `SecurityIncident` (C), partly resolving discrepancy X3. E3 §6: Defender for Endpoint documented for Windows only; BYOD compliance in report-only; 7 ASR rules in Audit (C) |
| Visibility gap | The Defender XDR connector exists and carries alerts (`SecurityAlert`, `SecurityIncident`) into the workspace (E7 §1). However, **raw endpoint telemetry** (process execution, network connections, logon events from advanced hunting tables such as `DeviceEvents`, `DeviceLogonEvents`) does not appear to be forwarded and remains in the Defender portal with 30-day retention. Intune and DLP data stay in their own portals. Non-Windows device coverage is not documented. The gap is narrower than previously assessed (alerts do reach Sentinel) but real (raw events for investigation do not, and retention is short). |
| Attacker activity that could go unobserved in Sentinel | Disabling device compliance or security policies in Intune; DLP events showing customer data leaving; endpoint activity on unmanaged or non-Windows devices. Much of this would still be visible in the Defender and Purview portals if someone looks there (I). |
| Business and security consequences | Alerts split across several portals for a two-person team; slower correlation; evidence for endpoint investigations kept for only 30 days. |
| What closes the gap | Confirm and, if missing, enable the Defender XDR connector; forward Intune audit logs to the workspace; bring DLP alerts into the incident queue; confirm Defender coverage for macOS. |
| Implementation difficulty | **Low–Medium.** Mostly connectors within existing Microsoft licensing (E5 for 120 users). |
| Priority and rationale | **Medium.** The data largely exists in Microsoft portals, so this is mainly a correlation and efficiency gap, not total blindness. |
| Dependencies and validation | Defender XDR connector status (Q4). Licensing for the E3/F3 population. |

### G10 — Coverage not documented

| Field | Detail |
|---|---|
| Gap ID | G10 |
| Affected system | Key Vault `kv-finserve-prod`; API Management; Azure Functions; Cache for Redis; Azure DevOps pipelines and service principals; Azure Automation; shared file services; ExpressRoute gateway; Cloudflare; customer authentication and SCA events |
| Evidence source | These systems appear in E1 §2, E2 §1-§5, E3 §2 and E4 §2 but in none of the architecture logging tables (E1 §6, E2 §7, E3 §7). E2 §7's general statement that all resource diagnostics are sent is contradicted by the Storage gap (X2). **Note:** Entra Connect was previously listed here but is now confirmed as forwarding Windows Security Events via AMA (E7 §2: `ENTRACONNECT-01` using `dcr-security-events-common`). It has been moved to the identity section of `Detection-Surface.md`. |
| Visibility gap | The SOC cannot say whether these systems are monitored. |
| Attacker activity that could go unobserved | Possibly: reading secrets from Key Vault; misuse of the pipeline service principal with Contributor on `sub-prod`; customer account takeover. |
| Business and security consequences | If unmonitored, several would rank High or Critical: Key Vault holds connection strings and API keys; customer authentication is central to fraud detection. |
| What closes the gap | Validation first: confirm diagnostic settings, agents and connectors for each system; then rate each one using the method in Section 3. |
| Implementation difficulty | **Unknown** until validated. |
| Priority and rationale | **Provisional.** Key Vault and customer authentication are likely High because of what they protect. |
| Dependencies and validation | Q10, Q11, Q12, Q13. |

## 6. Detection Coverage Gaps vs. Log Retention Gaps

### 6.1 Two different problems

- A **detection coverage gap** means the SOC may not receive or analyse the security events needed to detect an attack. The events either never reach Sentinel, or they arrive and nothing looks at them.
- A **log retention gap** means the events were collected, but are deleted before an investigation needs them.

They need different fixes. **Longer retention cannot recover events that were never collected.** Extending the workspace to one year would not help with G1, G2 or G4, because no SQL audit, blob access or Kubernetes audit events exist in the workspace to keep. The reverse is also true: the SQL audit is kept for one year in storage, so it is **investigable but not detectable** — a retention strength with a coverage gap.

### 6.2 Retention by source

| Source | Where kept | Period | In Sentinel? | Evidence |
|---|---|---|---|---|
| Branch firewalls | On device | 14 days | No | E1 §6 (C) |
| DC-SLO SFTP server | Local syslog | 30 days | No | E1 §6 (C) |
| AKS control-plane and container logs | Workspace | 30 days | Yes (documented) | E1 §6 (C) |
| Defender for Endpoint raw events | Defender portal (Sentinel unclear) | 30 days | Unknown | E3 §7 (C); X3 |
| Entra ID sign-in logs (native copy) | Entra ID | 30 days | Also in workspace | E3 §7 (C) |
| Workspace default (Azure Activity, Entra, Firewall, WAF, App Service, VPN, JUMP-01, DCs, Fortigate, Defender for Cloud, M365) | Workspace | 60 days | Yes (documented) | E1 §6, E2 §7, E3 §7 (C) |
| Unified Audit Log, E3/F3 users (330) | Purview | 90 days | Subset via connector (I) | E3 §7 (C) |
| Unified Audit Log, E5 users (120) | Purview | 180 days | Subset via connector (I) | E3 §7 (C) |
| Defender for Endpoint alerts; DLP incidents | Defender / Purview | 180 days | Unknown / No | E3 §7 (C) |
| Azure SQL MI audit | Immutable storage | 1 year | No | E1 §6 (C) |
| Intune audit | Intune | 1 year | No | E3 §7 (C) |
| Corebridge application logs | Corebridge | "Per contract" | No | E1 §6 (C); period Unknown |

### 6.3 What 60 days means in practice

Investigations rarely start on the day an attack starts. If an intrusion begins on day 1 and is discovered on day 75, the first 15 days of workspace data have already gone — typically the period that shows **how the attacker got in**. For sources held for 30 days or less (AKS, SFTP server, endpoint raw events, branch firewalls), the window is shorter still.

The practical consequences for FinServe are:

- The SOC may be unable to establish when an intrusion started, which matters for deciding which customers and records were affected.
- Breach notifications and regulatory responses may have to state a wider, less precise scope.
- With a median time to first touch of about six hours and no out-of-hours rota (E5; E6), slow detection makes the retention window more important, not less.
- Different sources expire at different times (14, 30, 60, 90, 180 days), so an investigation can lose its correlating evidence piece by piece.

### 6.4 Is one year required?

The supplied documents do **not** state a regulatory or contractual requirement to keep security logs for a specific period. The 5-year and 7-year periods in E3 §8 and E4 §6 relate to customer records under the Money Laundering Regulations, not to security event logs, and should not be applied to them. UK GDPR Article 32 (E1 §7) requires the ability to detect and investigate a personal data breach, but does not set a log retention period.

One year is therefore a **recommendation based on investigation need, not a confirmed regulatory requirement.** Before proposing it again, the SOC should:

1. Ask Compliance and the DPO whether any obligation, policy or contract sets a period (Q15).
2. Confirm whether the earlier request was rejected or deferred (discrepancy X4), and on what grounds.
3. Present options rather than a single cost: for example, keeping high-value tables (Entra ID, Azure Activity, SQL audit once collected) longer than high-volume ones, or using lower-cost long-term storage tiers for investigation-only data. Costs have not been estimated in this assessment.

## 7. SOC operating observations

### 7.1 Alert statistics (reported by Marcus Ifill, last 30 days)

| Measure | Value | Calculation |
|---|---|---|
| Total alerts | 847 | Reported (R) |
| Closed as benign positive or false positive | 812 — **95.9%** | 812 ÷ 847 |
| Closed as informational | 31 — **3.7%** | 31 ÷ 847 |
| Properly investigated | 4 — **0.5%** | 4 ÷ 847 (0.47%) |
| Check | 812 + 31 + 4 = 847 | All alerts are accounted for |
| Approximate daily volume | **~28 alerts per day** | 847 ÷ 30 = 28.2 |
| Per analyst | **~14 alerts per analyst per day** | 28.2 ÷ 2, assuming both analysts triage full time (I) |
| Median time to first touch | **~6 hours** | Reported (R) |

### 7.2 What these figures suggest

These figures describe outcomes, not quality. They do **not** prove that the 843 alerts not investigated were handled wrongly; many may genuinely have been benign. What they do suggest:

- **Alert fatigue.** When 96% of alerts are closed as benign or false positive, analysts learn to expect noise, and a real alert is more likely to be closed quickly or missed.
- **Rule tuning.** Built-in templates running with default settings (E5) are a common source of noise. Tuning them to FinServe's normal activity (known admin IPs, service accounts, the FinRecon mailbox) should reduce volume.
- **Analyst workload.** About 14 alerts per analyst per day leaves little time for investigation, rule tuning or the detection work in the backlog.
- **Investigation quality.** Four investigations in 30 days means the SOC has very little recent practice investigating, and its procedures are rarely tested.
- **Detection effectiveness.** Most alerts come from identity, Azure Activity and firewall templates, which matches where the rules are. Volume does not mean coverage: the noisiest areas are not the highest-risk ones (G1, G2, G4).
- **Staffing constraints.** Two analysts, no out-of-hours rota and alerts paging one person's phone (E6) explain the six-hour median. An attack starting in the evening may not be looked at until the next morning.

### 7.3 What we need to confirm these observations

A breakdown of the 847 alerts by rule, severity and closure reason; a sample of closed incidents with their notes; and how the four investigated alerts were chosen (Q16).

## 8. Recommended next steps

In priority order. None of these changes should be made without authorisation from Marcus Ifill and the CISO.

1. **Report G1 and G2 to the CISO now** as Critical, together with the plain-text settlement credential noted in G3.
2. **Obtain read-only workspace access** and complete the validation checks in `Detection-Surface.md` Section 6.3, turning Unknowns into findings.
3. **Close G1, G2 and G4** by sending SQL MI audit, blob access and AKS audit logs to the workspace, after a volume and cost estimate.
4. **Start on G5 immediately**, because it needs no new data: inventory and tune existing rules, then build the Category A detections in `Detection-Backlog.md`.
5. **Inventory Slough before the Head of Infrastructure leaves** and forward the SFTP server logs (G3).
6. **Raise third-party log access with the GRC track** for supplier and contract follow-up (G6).
7. **Decide retention separately** once coverage is fixed, using the options in Section 6.4.

## 9. Questions for Marcus and the mentor

Answers would change the findings above. All gap ratings are **provisional** until these are answered. No answers have been assumed.

| # | Priority | Question | Why it matters | Gaps affected |
|---|---|---|---|---|
| Q1 | 1 | Can we have Microsoft Sentinel Reader and Log Analytics Reader on `law-sentinel-prod`, and read access to diagnostic settings across the six subscriptions? | Without it nothing can move beyond "documented"; this is the single biggest limit on the assessment. | All |
| Q2 | 1 | Can we see the full analytics rule inventory, including disabled rules, and the four custom KQL rules? Which two are uncertain, and why? | Determines real detection coverage; uncertain custom rules may not work at all. | G5 |
| Q3 | 1 | Are all enabled connectors actively ingesting? Have there been ingestion failures, data collection filters or per-table retention different from 60 days? | An enabled connector does not prove data is arriving. | All |
| Q4 | 1 | Is the Microsoft Defender XDR connector enabled? Do Defender for Endpoint and Defender for Office 365 alerts or raw events reach the workspace? | Resolves discrepancy X3 and endpoint visibility, including branches. | G8, G9 |
| Q5 | 2 | Which AKS diagnostic categories are enabled (for example `kube-audit`, `kube-audit-admin`, `kube-apiserver`)? | Resolves discrepancy X1. | G4 |
| Q6 | 2 | Which Defender for Cloud plans are enabled on `sub-prod` (Servers, SQL, Storage, Containers)? | Defender for SQL and Storage could give partial alerting for G1 and G2. | G1, G2 |
| Q7 | 2 | Which audit action groups are configured on `sqlmi-prod`? Is SQL auditing enabled on `sqldb-uat`? Why has the SQL audit connector not been enabled after two requests? | Determines what DET-01 can detect, and the UAT exposure. | G1, G7 |
| Q8 | 2 | What are the other DC-SLO workloads? What operating system and logging does the SFTP server use, and can it forward syslog? How does Solvex connect for remote support? | Slough is the largest Unknown; the expert is leaving. | G3, G6 |
| Q9 | 3 | What model are the branch firewalls, and can they export syslog over the VPN? | Determines how G8 can be closed. | G8 |
| Q10 | 3 | Which Windows event IDs does the data collection rule gather from the domain controllers and JUMP-01? Is the Entra Connect server onboarded? | Determines whether DET-08 can work, and G10. | G5, G10 |
| Q11 | 3 | Are diagnostic settings enforced by Azure Policy? Which resources have them (Key Vault, APIM, Functions, Redis, Storage, file services)? | Resolves discrepancy X2. | G2, G7, G10 |
| Q12 | 3 | Does the Entra ID connector include non-interactive and service-principal sign-in logs? | Needed for DET-04 and for the pipeline service principal. | G5, G10 |
| Q13 | 3 | Where are customer login and SCA events recorded, and can the SOC see them? | Customer account takeover detection. | G10 |
| Q14 | 3 | What does the Corebridge contract allow: log types, format, ticket turnaround, retention, security-event notification? | Determines G6 options. | G6 |
| Q15 | 4 | Is there a documented regulatory, legal or policy requirement for security log retention? Was the one-year request rejected or deferred, and why? | Resolves discrepancy X4; frames the retention recommendation. | Retention |
| Q16 | 4 | Can we see the 847 alerts broken down by rule, severity and closure reason, plus sample closed incidents? How were the four investigated alerts selected? | Tests the operating observations in Section 7. | G5 |
