# Risk Register - Project Sentinel

FinServe Digital Bank Ltd

## Scoring methodology

18 risks, scored on a 5x5 likelihood-impact matrix (score = likelihood x impact, maximum 25). This is our own scale, not FinServe's. Where FinServe's register carries a risk at a different score, we state both and explain the difference. Owners are drafted at executive level per FinServe convention and must be confirmed with each named owner during W2.

Each risk is scored twice: inherent (no controls) and residual (with the controls evidenced from the architecture documents, not controls that are planned, budgeted or promised).

Risks are written in cause-event-consequence form: Because \[cause\], there is a risk that \[event\], resulting in \[consequence\].

### Likelihood scale

| Score | Level | Definition |
| --- | --- | --- |
| 1 | Rare | Could occur in exceptional circumstances; no precedent |
| 2 | Unlikely | Could occur but not expected in the next 12 months |
| 3 | Possible | Has occurred elsewhere or conditions exist that make it plausible |
| 4 | Likely | Has occurred at FinServe or conditions strongly favour occurrence |
| 5 | Almost certain | Expected to occur; known active conditions or past incidents |

### Impact scale

| Score | Level | Definition |
| --- | --- | --- |
| 1 | Negligible | Minor inconvenience; no customer, financial or regulatory impact |
| 2 | Minor | Limited customer impact, recoverable within hours, no regulatory interest |
| 3 | Moderate | Noticeable customer impact, financial loss under 500k, potential regulatory inquiry |
| 4 | Major | Significant customer detriment, financial loss 500k-5m, likely regulatory action, reputational damage |
| 5 | Severe | Widespread customer harm, financial loss over 5m, enforcement action, threat to authorisation or funding round |

### Risk appetite bands

| Score | Band | Treatment |
| --- | --- | --- |
| 1-4 | Low | Accept and monitor |
| 5-9 | Moderate | Manage within existing controls; schedule improvement |
| 10-15 | High | Remediate within the current quarter; escalate to executive |
| 16-25 | Critical | Immediate action required; escalate to board |

## Identity and access

### RS-01: Standing privileged access across the Azure and Entra estate

Because privileged roles in Entra ID and Azure are permanently assigned with no just-in-time activation, periodic recertification or privileged access standard, and because PIM is licensed but unconfigured for 16 months since the audit finding, there is a risk that a compromised privileged account provides an attacker persistent administrative access to production systems and customer data, resulting in a data breach affecting up to 180,000 customers, regulatory enforcement and reputational damage during the funding round.

| Field | Value |
| --- | --- |
| Assets | A-14 (Entra ID), A-05 (SQL MI), A-08 (Key Vault), all production |
| Data | D1, D2, D3, D7 |
| Inherent | L4 x I5 = 20 |
| Controls evidenced | MFA on admin roles (CA policy 2, 4h sign-in frequency). Break-glass alerting in Sentinel. |
| Residual | L3 x I5 = 15 (High) |
| Owner | CTO |
| FinServe score | Not on the register. Audit finding IA-2024-07 is open, deferred once, no compensating control proposed. |
| Recommended treatment | Configure PIM for all privileged Entra ID and Azure roles. Implement recertification on a quarterly cycle. Publish a privileged access standard. Interim: reduce standing Owner assignments from 14 to minimum necessary. |

### RS-02: No tiered admin model in Active Directory

Because Domain Admins is a single group with 6 members who also hold day-to-day workstation accounts, there is a risk that credential theft from a workstation (phishing, malware, pass-the-hash) gives an attacker domain-level control, resulting in compromise of the on-premises directory that syncs to Entra ID via Entra Connect, potentially affecting the entire identity estate.

| Field | Value |
| --- | --- |
| Assets | A-15 (AD), A-16 (Entra Connect), A-14 (Entra ID via sync) |
| Data | D6, D7 |
| Inherent | L4 x I5 = 20 |
| Controls evidenced | MFA required for Azure/M365 access via Conditional Access. No evidenced MFA for on-premises administration (RDP, AD admin tools). Entra Connect sync limited to password hash. |
| Residual | L3 x I5 = 15 (High) |
| Owner | CTO |
| FinServe score | Not on the register |
| Recommended treatment | Implement tiered admin model: separate admin accounts for domain administration, never used for daily work. Remove day-to-day accounts from Domain Admins. Deploy PAW or secured admin workstations for AD management. |

### RS-03: FinRecon basic authentication bypass weakens tenant security posture

Because the FinRecon reconciliation tool authenticates to Exchange Online via basic auth over IMAP, requiring a Conditional Access exclusion (CA-Exclusions-Service group) that also exempts it from the legacy auth block and geo-blocking policies, there is a risk that the shared mailbox credential is compromised and used for unauthorised mailbox access or as a pivot into the tenant, resulting in exposure of D3 financial data in reconciliation emails and potential lateral movement.

| Field | Value |
| --- | --- |
| Assets | A-18 (Exchange Online), A-24 (FinRecon), A-14 (Entra ID) |
| Data | D3 |
| Inherent | L4 x I4 = 16 |
| Controls evidenced | The exclusion group is documented (CHG-2023-0447). Mailbox audit logging is on. The exclusion has been reviewed and renewed twice. |
| Residual | L3 x I4 = 12 (High) |
| Owner | CTO / Head of Digital Workplace |
| FinServe score | Not on the register. IA-2024-02 was closed; the exclusion was not identified in the audit working papers. |
| Recommended treatment | Escalate vendor OAuth timeline. If no committed date, evaluate replacement tools. As interim, scope the CA exclusion to the FinRecon service account only (remove from the group carrying break-glass and other service accounts) and restrict to the DC-SLO source IP. |

### RS-04: Administrative access through a single jump box with IP allowlist

Because all administrative access to production routes through JUMP-01 via RDP, with access controlled by an IP allowlist of HQ egress and four named home addresses rather than Azure Bastion, there is a risk that the jump box is compromised (RDP vulnerability, credential theft, or a compromised home network on the allowlist), resulting in direct administrative access to all production assets.

| Field | Value |
| --- | --- |
| Assets | A-17 (JUMP-01), all production assets |
| Data | D1 through D7 (via admin access) |
| Inherent | L3 x I5 = 15 |
| Controls evidenced | IP allowlist. JUMP-01 security event logs forwarded to Sentinel via AMA. Windows Server 2022 (current). |
| Residual | L2 x I5 = 10 (High) |
| Owner | Head of Infrastructure |
| FinServe score | Not on the register |
| Recommended treatment | Replace JUMP-01 with Azure Bastion (previously evaluated and deferred on cost in 2024). As interim, enforce MFA on RDP sessions to JUMP-01 and review the home IP allowlist quarterly. |

## Data protection

### RS-05: Unmasked restricted data in the non-production environment

Because the nightly UAT data refresh (F10) copies account numbers, balances, transaction history and NI numbers unmasked to sqldb-uat for referential consistency, and because the non-production subscription runs audit-only Azure Policy and free-tier Defender, there is a risk that restricted production data (D2, D3) is accessed through the weaker non-production controls by the 21 users with Contributor access, resulting in a personal data breach affecting up to 180,000 customers that would require ICO notification.

| Field | Value |
| --- | --- |
| Assets | A-28 (sqldb-uat), A-05 (sqlmi-prod via CHG-2024-0881) |
| Data | D1 (partial), D2 (NI numbers), D3 |
| Inherent | L4 x I5 = 20 |
| Controls evidenced | Names and emails masked. TDE encryption on UAT database. Firewall exception CHG-2024-0881 limits to port 1433 from UAT App Service only. |
| Residual | L3 x I4 = 12 (High) |
| Owner | CTO |
| FinServe score | Not on the register. No risk entry relating to non-production environments. |
| Recommended treatment | Extend masking to NI numbers, account numbers and balances. If referential consistency requires real account numbers, implement tokenisation. Remove or set an expiry on CHG-2024-0881. Apply the landing-zone policy initiative to sub-nonprod in enforce mode. |

### RS-06: Data retention exceeds legal basis and has no disposition review

Because a tenant-wide 7-year retention policy is applied uniformly to all M365 content without a signed retention schedule, and because this exceeds the MLR 2017 requirement of 5 years from end of relationship, there is a risk that FinServe retains personal data beyond its lawful basis, resulting in a breach of the UK GDPR storage limitation principle and potential ICO enforcement.

| Field | Value |
| --- | --- |
| Assets | A-18 (Exchange), A-19 (SharePoint/OneDrive), A-20 (Teams) |
| Data | D1, D3, D6 |
| Inherent | L5 x I3 = 15 |
| Controls evidenced | Retention policy is configured and applied. A draft schedule (v0.9) exists but is unsigned. |
| Residual | L4 x I3 = 12 (High) |
| Owner | General Counsel / DPO |
| FinServe score | Not scored as a risk. Audit finding IA-2024-11 is open with no revised target date. |
| Recommended treatment | Sign off the draft retention schedule. Implement differentiated retention by data category. Add disposition review. Address D5 behavioural data in SQL (no deletion routine since 2023 launch). |

### RS-07: Cross-border data transfers without adequate transfer mechanisms

Because Textway routes SMS through a Singapore aggregator and Solvex provides support from Bengaluru, both without an IDTA or UK Addendum, and because the 2024 legal opinion covered only the Microsoft arrangement, there is a risk that FinServe is transferring personal data (D1, D3) to countries without adequate protection and no lawful transfer mechanism, resulting in a UK GDPR Chapter V breach and potential ICO enforcement.

| Field | Value |
| --- | --- |
| Assets | A-23 (DC-SLO, via Solvex support), A-24 (FinRecon), external (Textway) |
| Data | D1 (phone numbers via Textway), D3 (transaction amounts via Textway; reconciliation data via Solvex) |
| Inherent | L5 x I4 = 20 |
| Controls evidenced | The transfers are identified in the 2025 data mapping exercise. The Textway path is documented as not yet assessed. |
| Residual | L5 x I3 = 15 (High) |
| Owner | General Counsel / DPO |
| FinServe score | Not on the register |
| Recommended treatment | Commission legal assessment of both transfer paths. Execute IDTAs or UK Addendums. Perform supplier due diligence on Textway and Solvex. If neither can provide adequate safeguards, evaluate replacement suppliers with UK or adequacy-country processing. |

### RS-08: Behavioural data retained indefinitely with no legal basis

Because the dbo.SessionTelemetry table in Azure SQL MI has accumulated D5 behavioural data since the 2023 launch with no deletion routine and no identified retention basis, there is a risk that FinServe retains personal data indefinitely without a lawful basis, resulting in a storage limitation breach and an expanding dataset that increases breach impact over time.

| Field | Value |
| --- | --- |
| Assets | A-05 (sqlmi-prod) |
| Data | D5 |
| Inherent | L5 x I2 = 10 |
| Controls evidenced | None for deletion. TDE encryption at rest. Private endpoint access. |
| Residual | L5 x I2 = 10 (High) |
| Owner | CTO |
| FinServe score | Not on the register |
| Recommended treatment | Define a retention period for D5 data with a lawful basis. Implement an automated deletion routine. Backfill: purge data beyond the agreed retention period. |

## Operational resilience

### RS-09: Settlement process not classified as an important business service

Because the end-of-day settlement and reconciliation process (P8) was excluded from the important business services list on the basis that it is not customer-facing, despite being the mechanism that confirms every payment the bank makes, there is a risk that a P8 failure is not governed by an impact tolerance, tested or subject to the mapping requirements of PRA SS1/21, resulting in a settlement failure that FinServe has not prepared for and cannot recover from within a defined window.

| Field | Value |
| --- | --- |
| Assets | A-23 (DC-SLO SFTP), A-24 (FinRecon), A-18 (Exchange, shared mailbox), external (Corebridge, Meridian Trust) |
| Data | D3 |
| Inherent | L3 x I5 = 15 |
| Controls evidenced | Documented manual fallback (4 hours, used twice, last in 2024). Finance Operations team of 6. Process owner (Nadia Ferreira) identified. |
| Residual | L3 x I4 = 12 (High) |
| Owner | COO (process owner is Head of Finance Operations) |
| FinServe score | R-17 covers operational resilience broadly at score 12, but does not specifically address P8's exclusion from the IBS list. |
| Recommended treatment | Reassess P8 for inclusion as an important business service. Set an impact tolerance. Map its dependencies (SFTP server, FinRecon, Meridian Trust, Exchange shared mailbox). Test the manual fallback under realistic conditions. |

### RS-10: Single point of failure in the SCA payment path

Because Textway is the sole SMS provider for Strong Customer Authentication one-time passcodes on payment initiation (\~48,000/day), with no configured fallback, there is a risk that a Textway outage prevents customers from authorising payments, resulting in a breach of the IBS-1 impact tolerance (4 hours) and potential regulatory scrutiny under the Payment Services Regulations.

| Field | Value |
| --- | --- |
| Assets | External (Textway), affects IBS-1 |
| Data | D1, D3 (in transit) |
| Inherent | L3 x I5 = 15 |
| Controls evidenced | No controls reducing likelihood. Impact mitigated only by the 4-hour IBS-1 tolerance window, which the manual customer workaround (visit a branch, call the contact centre) does not meaningfully reduce for 180,000 customers. No fallback path. No contractual SLA beyond reseller terms. |
| Residual | L3 x I5 = 15 (High) |
| Owner | COO |
| FinServe score | Not on the register |
| Recommended treatment | Implement a fallback OTP delivery method (push notification, authenticator app, or second SMS provider). Negotiate a proper contract with SLA. Conduct a supplier assessment. |

### RS-11: Key-person dependency on the Slough estate with imminent departure

Because Tobi Okonkwo (Head of Infrastructure) holds the deepest knowledge of the DC-SLO estate and the Kestrel-era processes and is leaving in 8 weeks, and because no successor has been appointed, there is a risk that critical operational knowledge of the settlement process, the SFTP server, the Fortigate configuration and 11 remaining Slough workloads is lost, resulting in inability to operate, troubleshoot or decommission the legacy estate.

| Field | Value |
| --- | --- |
| Assets | A-23 (DC-SLO SFTP), A-25 (Fortigate), A-24 (FinRecon), all DC-SLO workloads |
| Data | D3 |
| Inherent | L5 x I4 = 20 |
| Controls evidenced | Risk R-11 exists on FinServe's register at score 16. Documented manual fallback for P8. No successor appointed; no knowledge transfer plan evidenced. |
| Residual | L5 x I4 = 20 (Critical) |
| Owner | CTO |
| FinServe score | R-11 at 16. We agree with the score but note that with departure confirmed and no evidenced knowledge transfer plan, the residual equals the inherent. The score will only move down when knowledge transfer is demonstrably in progress. |
| Recommended treatment | Immediate knowledge transfer sessions covering DC-SLO operations, SFTP configuration, Fortigate rules and the settlement process. Document all Kestrel-era processes before departure. Accelerate successor appointment. |

## Detection and response

### RS-12: Sentinel coverage gaps leave critical data stores unmonitored

Because the Azure SQL audit connector, Storage diagnostics and AKS audit log are not enabled in Sentinel, and because branch firewall logs and the DC-SLO SFTP server logs are local only, there is a risk that malicious activity against the bank's primary customer database, document store, container platform, branch networks and settlement infrastructure goes undetected, resulting in delayed incident response and an inability to meet the 72-hour ICO breach notification deadline.

| Field | Value |
| --- | --- |
| Assets | A-05 (SQL MI), A-06 (Storage), A-01 (AKS), A-23 (DC-SLO SFTP), A-27 (branches) |
| Data | D1, D2, D3 |
| Inherent | L4 x I5 = 20 |
| Controls evidenced | Azure Firewall logs, Entra ID sign-in/audit, Front Door/WAF logs, VPN Gateway logs, JUMP-01 security events all feed Sentinel. Partial coverage exists. |
| Residual | L3 x I4 = 12 (High) |
| Owner | CISO |
| FinServe score | R-09 (ransomware) at 16 is the nearest, but it describes the event not the detection gap. No risk entry specifically for Sentinel coverage. |
| Recommended treatment | Enable the Azure SQL audit connector (raised twice by SOC manager, not actioned). Enable Storage diagnostics and AKS audit log connectors. Onboard branch firewall logs and DC-SLO SFTP logs to Sentinel. |

### RS-13: Two-person SOC with no after-hours coverage

Because the security function has 3 staff (CISO, SOC manager, analyst who joined September 2025) with no after-hours rota, and because out-of-hours alerting pages one mobile phone, there is a risk that a security incident occurring outside business hours is not detected or responded to for up to 14 hours, resulting in extended attacker dwell time and greater customer data exposure.

| Field | Value |
| --- | --- |
| Assets | A-30 (Sentinel), all production |
| Data | All |
| Inherent | L4 x I4 = 16 |
| Controls evidenced | Sentinel automated alerting. Break-glass account sign-in alerting. Microsoft Defender for Cloud alerts. The approved security engineer role has not been opened. |
| Residual | L3 x I4 = 12 (High) |
| Owner | CISO |
| FinServe score | Not on the register |
| Recommended treatment | Open the budgeted security engineer requisition. Establish an on-call rota with at least two people. Evaluate a managed SOC or MDR service for after-hours coverage as an interim measure. |

### RS-14: 60-day log retention limits investigation and compliance capability

Because Log Analytics workspace retention is 60 days across the board (extending retention priced and deferred), and because Unified Audit Log retention for 330 E3/F3 users is 90 days against the E5 cohort's 180, there is a risk that evidence needed for incident investigation, regulatory response or data subject access requests is unavailable if the triggering event is discovered after the retention window, resulting in inability to meet ICO notification obligations or respond to PRA/FCA inquiries.

| Field | Value |
| --- | --- |
| Assets | A-30 (Sentinel/Log Analytics), A-18 (Exchange, UAL) |
| Data | D5, D7 |
| Inherent | L4 x I3 = 12 |
| Controls evidenced | SQL MI audit logs retained for 1 year in immutable storage (separate from Sentinel). Defender for Endpoint retains 180 days of alerts. |
| Residual | L4 x I3 = 12 (High). An attacker active for 61 days leaves no record; a bank with a 72-hour ICO obligation cannot defend 60-day retention. |
| Owner | CISO |
| FinServe score | Not on the register |
| Recommended treatment | Extend Sentinel retention to at least 180 days for security-relevant sources. Equalise UAL retention across licence tiers. Archive older logs to a lower-cost storage tier if cost is the blocker. |

### RS-15: Static settlement credential in plaintext configuration

Because the DC-SLO SFTP server authenticates to Meridian Trust with a static password stored in plaintext in deliver.cfg, not rotated since February 2019, there is a risk that the credential is compromised (via access to the config file, backup, or the departing Head of Infrastructure's knowledge), resulting in unauthorised access to the settlement file exchange and potential manipulation of D3 financial data.

| Field | Value |
| --- | --- |
| Assets | A-23 (DC-SLO SFTP), external (Meridian Trust) |
| Data | D3 |
| Inherent | L4 x I4 = 16 |
| Controls evidenced | SFTP server is in DC-SLO, reachable only via ExpressRoute. Reconciliation process (FinRecon) would detect discrepancies the following morning. |
| Residual | L3 x I4 = 12 (High) |
| Owner | Head of Finance Operations |
| FinServe score | Not on the register |
| Recommended treatment | Rotate the credential immediately. Migrate to key-based authentication (recommended by Meridian Trust in their 2024 review). Remove the plaintext password from the config file and use a secrets manager. |

### RS-16: No technology internal audit in 2025

Because the 2025 IT audit was deferred to 2026 when the Corebridge migration review was deprioritised, and because the 2024 audit excluded non-production environments, third-party data processing, cloud configuration, data protection compliance and the Slough estate, there is a risk that control weaknesses in these areas remain unidentified by the third line of defence for over two years, resulting in an assurance gap the board may not be aware of.

| Field | Value |
| --- | --- |
| Assets | All |
| Data | All |
| Inherent | L5 x I3 = 15 |
| Controls evidenced | This review (Project Sentinel) partially fills the gap for the current period. Second-line risk function exists but CRO post is vacant. |
| Residual | L4 x I3 = 12 (High) |
| Owner | Head of Internal Audit (reports to Audit Committee) |
| FinServe score | Not on the register |
| Recommended treatment | Reinstate technology audit coverage for 2026 with scope covering the areas excluded in 2024. Brief the Audit Committee on the 2025 gap. |

### RS-17: Expiring service principal secret on legacy deployment pipelines

Because two older Azure DevOps pipelines authenticate to production with a service principal client secret last rotated in March 2024 with a two-year expiry, there is a risk that the secret expires without notice or is compromised, resulting in either loss of deployment capability for the affected pipelines or unauthorised production access via a leaked secret.

| Field | Value |
| --- | --- |
| Assets | A-31 (Azure DevOps), production workloads deployed by those pipelines |
| Data | D7 |
| Inherent | L4 x I3 = 12 |
| Controls evidenced | Key Vault stores the secret (soft delete, purge protection). Two newer pipelines use workload identity federation (correct pattern). |
| Residual | L3 x I3 = 9 (Moderate) |
| Owner | CTO |
| FinServe score | Not on the register |
| Recommended treatment | Migrate the two older pipelines to workload identity federation. Rotate the current secret immediately as an interim measure. Set a calendar reminder 60 days before the March 2026 expiry. |

### RS-18: Branch sites as unmonitored network entry points

Because branch LANs are flat with no VLAN segmentation below site level, and because branch firewall logs are not forwarded to Sentinel (14-day local retention only), there is a risk that a compromise at a branch (physical access to a counter terminal, a compromised staff device, lateral movement from the local internet breakout) is both easier to achieve and harder to detect than a compromise in the Azure estate, resulting in attacker access to customer data flowing through the branch and a pivot into the wider network via the S2S VPN.

| Field | Value |
| --- | --- |
| Assets | A-27 (branches), A-12 (VPN Gateway) |
| Data | D1, D3 |
| Inherent | L3 x I4 = 12 |
| Controls evidenced | S2S VPN authentication. Corporate laptops are Intune-managed with Defender for Endpoint. Split-tunnelling limits exposure to corporate-destined traffic. |
| Residual | L3 x I3 = 9 (Moderate) |
| Owner | COO |
| FinServe score | Not on the register |
| Recommended treatment | Deploy VLAN segmentation at each branch. Forward branch firewall logs to Sentinel. Review branch physical access controls. Reassess alongside the standing board review of branch viability (board worry item 4). |

## Comparison with FinServe's existing risk register

FinServe's register has 18 open risks. This register has 18 risks built from the architecture. The overlap is small, and the gaps tell the story.

### FinServe risks that survive contact with the architecture

| FinServe ID | Description | Their score | Our equivalent | Our residual | Comment |
| --- | --- | --- | --- | --- | --- |
| R-04 | Core banking outage | 20 | Not separately raised | - | Corebridge is a supplier risk (S-01) rated Medium. The outage risk is real but the controls (Business Critical SQL MI, Front Door failover, Corebridge MSA with SLA) are stronger than the score of 20 suggests. We would score the residual at 12. |
| R-09 | Ransomware | 16 | RS-12, RS-13 | 12 | The risk is valid but the register describes the event, not the detection gap that determines whether it succeeds. Our RS-12 and RS-13 address the underlying conditions. |
| R-11 | Key person dependency | 16 | RS-11 | 16 | Agreed, and now more urgent because the departure is confirmed. We score the inherent higher (20) because the risk has crystallised from possible to certain. |
| R-02 | Regulatory censure post cyber incident | 15 | Cross-cutting | - | This is a consequence, not a risk. Multiple of our risks (RS-01, RS-05, RS-07, RS-12) have regulatory enforcement as a consequence. A risk register entry for "the regulator might be unhappy" without specifying the cause is not actionable. |
| R-17 | Failure to meet impact tolerances | 12 | RS-09, RS-10 | 12-15 | Valid but too broad. Our RS-09 (P8 not on the IBS list) and RS-10 (Textway single point of failure) are the specific instances the architecture reveals. |

### FinServe risks not carried forward

R-02 (regulatory censure) is not carried forward as a standalone risk because it describes a consequence rather than a cause-event pair. The consequence appears across multiple risks in this register. R-04 (core banking outage) is not separately raised because the residual risk after evidenced controls is lower than FinServe's score of 20 suggests, and the supplier relationship is covered in S-01.

### Risks absent from FinServe's register

The following are on our register and have no equivalent on FinServe's:

- RS-01: Standing privileged access (corresponds to open audit finding IA-2024-07, but no risk register entry)
- RS-02: No tiered AD admin model
- RS-03: FinRecon basic auth bypass
- RS-04: JUMP-01 single admin path
- RS-05: Unmasked restricted data in UAT
- RS-06: Retention schedule (corresponds to open audit finding IA-2024-11, but no risk register entry)
- RS-07: Cross-border transfers without transfer mechanisms
- RS-08: Behavioural data retained indefinitely
- RS-10: Textway single point of failure
- RS-12: Sentinel coverage gaps
- RS-13: SOC capacity
- RS-14: Log retention
- RS-15: Static settlement credential
- RS-16: No 2025 IT audit
  - RS-17: Expiring service principal secret on legacy pipelines
  - RS-18: Branch sites as unmonitored network entry points

Sixteen of eighteen risks on this register have no entry on FinServe's. The register has no entry relating to third-party data processing, to non-production environments, to privileged access, to detection capability, or to data protection compliance. Two open audit findings (IA-2024-07, IA-2024-11) have management responses but no corresponding risk register entries, meaning the risks they describe are not being tracked, scored or reported to the Risk Committee.
