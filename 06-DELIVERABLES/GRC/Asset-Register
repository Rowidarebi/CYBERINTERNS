# Asset Register - Project Sentinel

FinServe Digital Bank Ltd

## Approach

29 assets, grouped by function. Granularity rule: an asset gets its own row if it can fail independently and that failure would affect a specific business service or data category. "Azure Production" as one entry (FinServe's current register) masks which failures affect which services. One entry per Azure resource (\~1,180 lines) is unusable for risk assessment.

This register was rebuilt from the architecture documents (02-ARCHITECTURE), not from FinServe's existing 41-entry register. Where FinServe's register makes a claim the architecture does not support, the discrepancy is noted in the final section.

### Data category key

Per 04-Data-Flow.md:

| Code | Category | Sensitivity |
| --- | --- | --- |
| D1 | Identity (name, DOB, address, phone, email) | Confidential |
| D2 | Identity documents (NI number, passport/licence images) | Restricted |
| D3 | Financial (account number, balance, transaction history) | Restricted |
| D4 | Card (PAN, expiry, tokenised credentials) | Restricted (PCI) |
| D5 | Behavioural (device ID, IP, session, app telemetry) | Internal |
| D6 | Employee (HR records, payroll, performance) | Confidential |
| D7 | Credentials (password hashes, tokens, API keys) | Restricted |

### Criticality scale

| Rating | Definition |
| --- | --- |
| Critical | Failure causes immediate customer detriment or regulatory breach; maps to an IBS with a tolerance of 4 hours or less |
| High | Failure degrades a customer-facing service or exposes restricted data; recovery needed within one business day |
| Medium | Failure affects internal operations or non-production data; workaround exists |
| Low | Failure causes inconvenience; no direct customer or regulatory impact |

## Customer-facing compute

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-01 | AKS cluster (sentinel-prod) | Kubernetes cluster running 11 microservices: accounts, payments, cards, notifications, statements, onboarding, limits, disputes, audit-log, fx, API gateway. 3 system + 6 user nodes. Single region (uksouth); ukwest cluster scaled to zero, manual failover untested. | CTO | Production | D1, D2, D3, D5, D7 | Critical | IBS-1, IBS-2, IBS-3, IBS-4, IBS-5 |
| A-02 | App Service (internet banking) | Internet banking web frontend on P2v3 plan. Bypasses API Management and connects directly to Azure SQL MI. This bypass was a Lighthouse-era decision, never revisited. | CTO | Production | D1, D3, D5 | Critical | IBS-2 |
| A-03 | Azure Functions | Batch processing and webhook handlers. Reads from and writes to the document storage account. | CTO | Production | D2, D3 | High | None directly |
| A-04 | API Management (Developer tier) | API gateway for mobile app traffic. Enforces subscription keys and rate limits on AKS-bound requests. Developer tier noted; production workload on a non-production SKU. | CTO | Production | Transit only | Critical | IBS-1, IBS-2, IBS-3 |

## Data services

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-05 | Azure SQL MI (sqlmi-prod) | Primary customer database. Business Critical tier with secondary replica in ukwest. TDE encryption with service-managed key. 35-day PITR, weekly LTR. Sentinel audit connector not enabled; audit logging is on but not feeding the SIEM. D5 behavioural data (dbo.SessionTelemetry) has no deletion routine and has accumulated since 2023. | CTO | Production | D1, D3, D5 | Critical | IBS-1, IBS-2, IBS-3, IBS-4, IBS-5 |
| A-06 | Azure Storage (stfinservedocs) | Statements and uploaded KYC documents (passport/licence images, NI numbers). SSE with Microsoft-managed key. GRS, 30-day soft delete. | CTO | Production | D2, D3 | Critical | IBS-4 |
| A-07 | Azure Cache for Redis | Session tokens. TLS in transit. No backup (ephemeral by design). Loss causes mass session invalidation and re-authentication. | CTO | Production | D5, D7 | High | IBS-1, IBS-2, IBS-5 |
| A-08 | Key Vault (kv-finserve-prod) | Certificates, API keys, connection strings. HSM-backed Premium tier. Soft delete and purge protection enabled. Five of eleven AKS microservices do not use workload identity and authenticate to SQL MI with connection strings stored here as Kubernetes secrets. | CTO | Production | D7 | Critical | IBS-1, IBS-2, IBS-3, IBS-4, IBS-5 |

## Network and edge

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-09 | Azure Front Door + WAF | TLS termination and web application firewall for all customer-facing traffic. WAF in Prevention mode since March 2025. Provides regional failover between origins. | CTO | Production | Transit only | Critical | IBS-1, IBS-2, IBS-3, IBS-4, IBS-5 |
| A-10 | Azure Firewall Premium | Hub firewall controlling all inter-spoke and spoke-to-internet traffic. Two standing exceptions: CHG-2024-0881 (UAT to prod SQL MI on 1433, no expiry) and CHG-2025-0132 (dev to shared file server). | CTO | Platform | Transit only | Critical | All |
| A-11 | Cloudflare | External DNS and DDoS protection. Third-party dependency at the edge of the customer path. | CTO | External | Transit only | Critical | IBS-1, IBS-2, IBS-3 |
| A-12 | VPN Gateway (S2S + P2S) | Site-to-site tunnels to branches and DC-SLO. Point-to-site for \~120 concurrent remote staff. Entra ID authentication with MFA. | CTO | Platform | Transit only | High | None directly |
| A-13 | ExpressRoute Gateway | Private connectivity between HQ, DC-SLO and Azure. 1 Gbps from HQ, 500 Mbps from DC-SLO. Only HQ and DC-SLO have ExpressRoute; branches use S2S VPN. | CTO | Platform | Transit only | High | Supports all IBS indirectly |

## Identity and access

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-14 | Entra ID | Cloud identity provider. \~470 accounts. 9 Conditional Access policies. PIM licensed (P2) but not configured; all privileged roles are standing. Two break-glass accounts excluded from CA policies including MFA. CA-Exclusions-Service group also contains FinRecon shared mailbox (basic auth). | CTO | Cloud | D6, D7 | Critical | All |
| A-15 | Active Directory (finserve.local) | On-premises directory, authoritative for user objects. 2 domain controllers (Server 2019) in sub-identity. No tiered admin model; Domain Admins is a single group with 6 members who also hold day-to-day workstation accounts. | CTO | On-premises | D6, D7 | Critical | All (via sync) |
| A-16 | Entra Connect | Hybrid identity sync. Password hash synchronisation on a 30-minute cycle. Seamless SSO enabled. Runs on a dedicated server in sub-identity. Compromise of this server could allow credential manipulation across the entire estate. | CTO | Platform | D7 | Critical | All (via sync) |
| A-17 | JUMP-01 | Windows Server 2022 jump box in the hub VNet. Only administrative path to production. RDP (3389) permitted from HQ egress and four named home IPs. Azure Bastion was evaluated in 2024 and deferred on cost. | Head of Infrastructure | Platform | D7 | High | All (admin path) |

## Corporate services (Microsoft 365)

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-18 | Exchange Online | 470 user mailboxes, 38 shared mailboxes. EOP + Defender for Office 365 (Plan 2 for E5 users only; Plan 1 for E3). Anti-phishing impersonation protection covers 22 users (board/exec) and 3 domains. DMARC at p=none. Auto-forwarding to external blocked. The FinRecon shared mailbox authenticates via basic auth over IMAP (CA exclusion, renewed twice). | Head of Digital Workplace | Cloud | D1, D3, D6 | High | None directly, but P8 depends on it |
| A-19 | SharePoint Online / OneDrive | Document collaboration and storage. External sharing enabled (new and existing guests for SharePoint). Anonymous links permitted on 3 sites. 61 active guest accounts. Sensitivity labels published but adoption at 18%, no auto-labelling. | Head of Digital Workplace | Cloud | D1, D3, D6 | Medium | None directly |
| A-20 | Microsoft Teams | Collaboration. External federation open to all domains. 240 teams, no naming or expiry policy. Guest access enabled. DLP covers NI numbers and card data but not endpoint. | Head of Digital Workplace | Cloud | D1, D3, D6 | Medium | None directly |
| A-21 | Microsoft Intune | Device management. 355 Windows, 22 macOS, 95 corporate mobile, \~210 BYOD. Corporate devices enforced; BYOD compliance policy in report-only since February 2025. | Head of Digital Workplace | Cloud | D6 | High | Supports all indirectly |
| A-22 | Defender for Endpoint | EDR on corporate devices. Onboarded via Intune. 9 of 16 ASR rules in Block mode; 7 in Audit pending compatibility assessment started early 2025. Not on BYOD. | Head of Digital Workplace | Cloud | D5 | High | None directly |

## On-premises and legacy

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-23 | DC-SLO SFTP server | Receives Corebridge end-of-day settlement extract at 23:30, transforms and delivers to Meridian Trust at 00:15. Static credential in plaintext config (not rotated since 2019). Logs local only (syslog, 30 days on device, not in Sentinel). Key-person dependency on Tobi Okonkwo, departing in 8 weeks. | Head of Finance Operations | On-premises (Slough) | D3 | High | P8 (not classified as IBS; see notes) |
| A-24 | FinRecon | Desktop reconciliation tool (Solvex Systems, Bengaluru). Reads payment confirmation emails from Exchange Online shared mailbox via basic auth IMAP. Produces reconciliation report for Finance by 07:00. Vendor not on supplier register. Support access from India with no IDTA. | Head of Finance Operations | On-premises (Slough) | D3 | High | P8 |
| A-25 | Fortigate firewalls (HQ + DC-SLO) | Outbound web filtering for on-premises egress. Logs feed Sentinel via syslog. Branch sites have separate local firewalls whose logs do not feed Sentinel (14-day local retention only). | Head of Infrastructure | On-premises | Transit only | Medium | None directly |
| A-26 | HQ LAN (172.16.0.0/16) | Corporate LAN serving \~310 users. 2x500 Mbps diverse fibre. ExpressRoute to Azure. | Head of Infrastructure | On-premises (HQ) | Transit only | High | Supports all indirectly |
| A-27 | Branch sites (MAN, BIR, LEE) | Three legacy Kestrel branches serving \~4,100 customers. Flat LANs, no VLAN segmentation. Split-tunnel VPN to Azure. Local internet breakout for browsing. Branch firewall logs not in Sentinel. | COO | On-premises | D1, D3 | Medium | None directly |

## Non-production

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-28 | Azure SQL UAT (sqldb-uat) | Nightly refresh from production (F10). Masking script covers names and email addresses only. Account numbers, balances, transaction history and NI numbers are copied unmasked because the test pack depends on referential consistency. TDE encrypted. 7-day PITR. Standing firewall exception CHG-2024-0881 permits UAT App Service to reach sqlmi-prod on port 1433 with no expiry date. | CTO | Non-production | D1 (partial), D2 (NI numbers unmasked), D3 (unmasked) | High | None, but holds restricted production data |
| A-29 | Sandbox subscription (sub-sandbox) | Engineering experiments. No Azure Policy assigned. Defender for Cloud on free tier. 14 users hold Owner. Activity Log sent to Sentinel but resource-level diagnostics not enforced. Created for the platform team to trial services without change control. | CTO | Non-production | None stated | Low | None |

## Management and security tooling

| ID | Asset | Description | Owner | Env | Data | Criticality | IBS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-30 | Log Analytics + Microsoft Sentinel | SIEM. 60-day retention across all workspaces (extending retention priced and deferred). Connectors enabled for Azure Activity, Entra ID, M365, Defender for Cloud, Azure Firewall, WAF, threat intelligence. Not enabled: Azure SQL audit, Storage diagnostics, AKS audit log. Analytics rules are Microsoft built-in templates plus four custom KQL rules. No detection engineering backlog. Two-person SOC team; after-hours alerts page one mobile phone. | CISO | Platform | D5, D7 (security events) | High | Supports incident detection for all IBS |
| A-31 | Azure DevOps | Source control and CI/CD pipelines. Production pipeline uses workload identity federation. Two older pipelines use a service principal with client secret last rotated March 2024 (two-year expiry). \~15% of the Azure estate exists only in the portal, not in Terraform. | CTO | Platform | D7 (deployment credentials) | High | Supports all (deployment path) |

## Comparison with FinServe's existing register

FinServe's register has 41 entries with four fields (name, owner, environment, criticality). This register has 31 entries with eight fields, adding data categories, IBS mapping, and descriptive detail drawn from the architecture.

### What FinServe's register gets wrong

"Azure Production", "Azure Non-Production" and "Microsoft 365" as three entries is not a usable asset register. It tells you nothing about which failures affect which services, which data categories are at risk, or who is responsible for what. The register also has no data classification field, so it cannot support a data protection impact assessment or a breach notification decision.

### What this register adds

- Non-production environments with production data exposure (A-28, A-29)
- Individual data stores mapped to data categories (A-05 through A-08)
- The DC-SLO settlement path as distinct assets (A-23, A-24) rather than hidden inside "on-premises"
- Identity infrastructure separated by failure domain (A-14, A-15, A-16)
- Detection and response tooling (A-30) as an asset in its own right, since its failure means other failures go undetected
- Branch sites (A-27) with their logging blind spot

### What this register does not cover

Third-party systems (Corebridge, IDVerify, Textway, Meridian Trust) are in the supplier register, not here. This register covers FinServe's own assets. The interfaces to those third parties (API connections, SFTP endpoints, SMS paths) are described in the assets that use them.

Physical infrastructure (racks, power, cooling) at DC-SLO and HQ is out of scope per the engagement plan.
