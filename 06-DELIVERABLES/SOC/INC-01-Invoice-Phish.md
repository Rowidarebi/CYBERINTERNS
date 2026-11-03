# Incident Report INC-01: Reported phishing email and compromised mailbox session

**Project Sentinel · Inject 04, revised by Inject 06 and Inject 07 · SOC Track**

**Revised after Inject 06 (W3 D1): this is one incident. The report now also covers unauthorised access to the DC-SLO settlement SFTP server and a permitted connection to `sqldb-uat`. Sections 12 to 31 are new.**

**Reassessed after Inject 07 (W3 D2, Wednesday 21 October 2026): still one incident, still Critical, on a changed basis. The database the 04:11 flows reached holds a copy of production for 181,402 customers with only names and email addresses masked, and the refresh script the actor asked to open holds a shared production and UAT credential in plain text. Section 32 is new.**

| Item | Detail |
|---|---|
| Client | FinServe Digital Bank Ltd |
| Workstream | Security Operations (SOC) |
| Deliverable | `06-DELIVERABLES/SOC/INC-01-Invoice-Phish.md` |
| Companion | `Detection-Backlog.md`, Section 8 (detection gap: DET-10 and DET-11); `INC-01-Evidence-Requests.md` (Inject 06; Section 10 added for Inject 07) |
| References | Sentinel incident 2026-W2D1-0093; service desk ticket SD-2026-4417 |
| Date | 14 October 2026 (Inject 04). Revised 19 October 2026, W3 D1 (Inject 06). Reassessed 21 October 2026, W3 D2 (Inject 07). |
| Prepared by | SOC Team. Section 31 lists who wrote which part. |
| Status | **Provisional.** Built from the three inject artefacts and the existing 04-SOC documents. There is no tenant access and no query has been run. Section 8 lists what would be run and what I expect it to return. **Inject 06 update (Sections 12 to 31):** built from four further artefacts and the repository documents. Still no tenant or host access and no query run. Section 29 lists the added queries. **Inject 07 update (Section 32):** built from two further artefacts (I7-A1, I7-A2) and the repository documents. Still no tenant or host access and no query run. Section 32.12 lists the added assumptions, queries and questions. |

**How to read this report.** Every statement is tagged.

| Tag | Meaning |
|---|---|
| **[F] Fact** | Stated in an artefact or a source document. The reference is given. |
| **[A] Assessment** | My reasoning from the facts. Not directly evidenced. The reasoning is given. |
| **[U] Unknown** | Cannot be determined from what we hold. The query that would settle it is in Section 8. |
| **[H] Hypothesis** | Used from Section 12 onwards. A candidate explanation with no supporting artefact yet. A test is named. In Sections 1 to 11, [A] covers both assessment and hypothesis. |

From Section 12, confidence is **high** (an alternative would need a coincidence or a failure of the artefact itself), **moderate** (best explanation, at least one credible alternative) or **low** (possible, little that separates it from the alternatives).

## Revision notice (Inject 06, W3 D1)

- **Merged, not a second incident.** The Slough activity is assessed as the same intrusion (Section 14).
- **Severity is now Critical.** The trigger named in Section 6 has been met (Section 21).
- **Conclusions changed:** the rating (Sections 1 and 6), "no evidence of use of the Slough access" (Sections 5.3 and 6), the credential-rotation recommendation (Sections 7.2 and 7.3), and the Q9 expectation (Section 8). Each is marked **Superseded** or **Update** where it stands, and listed in Section 26.
- **New material:** incident overview (12), evidence and assumptions (13), relationship assessment (14), revised timeline (15), attack path reconstruction (16), database access assessment (17), evidence assessment (18), logging and investigation limitations (19), earliest possible compromise (20), severity reassessment (21), containment and recovery (22), evidence preservation (23), recommendations (24), references (25), then changes to Sections 1 to 11 (26), handoff to GRC (27), gaps (28), added queries (29), questions (30), contribution and AI use (31).

## Revision notice (Inject 07, W3 D2)

- **Still one incident, still Critical.** The tier does not change. Its basis does (Section 32.6).
- **What is new:** the database the 04:11 flows reached is a copy of production with only three fields masked (181,402 customers), and the script the actor asked to open holds a shared production and UAT credential in plain text. Use of the credential is not evidenced (Section 32.2).
- **The list of things I cannot rule out has grown** (Section 32.4.3). Nothing from Inject 06 was removed from it.
- **Nothing is deleted.** Earlier text stays as written. Notes marked "Update (Inject 07)" say where Section 32 adds to it, and Section 32.11 lists them.
- **New material:** Section 32, and Section 10 of `INC-01-Evidence-Requests.md` (ER-21 to ER-32).

## 1. Summary

- **What happened.** A Finance Operations user, Rachel Oduya (`r.oduya`), received a spoofed "Nadia Ferreira" email and, on the evidence, signed in on an attacker-controlled page. About 100 seconds after her "done" reply, a session using her token appeared from a hosting network in Manchester. Within 23 minutes it had created a concealing inbox rule, read her inbox and the "Settlement Ops (shared)" mailbox, and downloaded two files: `Settlement runbook v4.docx` and `DR-SLO access notes.txt`.
- **Rating.** Sentinel raised it as Medium ("Atypical travel"). I rate it **High, provisional**, rising to **Critical** if `DR-SLO access notes.txt` holds working access details (Section 6).
- **Superseded by Inject 06 (Sections 21 and 26): the rating is now Critical.** Logs from the Slough host show logins from the same address as the M365 session. The original text is kept above.
- **First three actions.** (1) Revoke Rachel's sessions and block sign-in. (2) Disable, not delete, the inbox rule named ".". (3) Copy the DC-SLO SFTP server's local logs off the box and phone Nadia Ferreira and Finance Operations to check no settlement instruction has changed.
- **Decision for the CISO.** Whether to rotate the static DC-SLO SFTP credential before tonight's settlement run, accepting a risk to settlement if it is done badly (Section 7.3).
- **Biggest unknown.** What the two downloaded files contain, and what the attacker did after 08:23:02 (Section 5.3).
- **Update (Inject 06):** still unknown, and joined by how the actor got from the downloads to a login on the Slough host, and what the connection to `sqldb-uat` did (Sections 16 and 17).
- **Update (Inject 07):** rating reconfirmed as Critical. `refresh_uat.ps1` is a credential store with reach into production, and `sqldb-uat` holds a copy of production for 181,402 customers (Section 32). Whether the credential was used is not established and cannot be established from what FinServe holds today.
- **Pattern.** Five of the six controls in the path behaved as configured. This is the same failure as SEC-2025-03 (June 2025), whose post-incident actions on DMARC enforcement and session revocation are still open (Section 4.3).

## 2. Sources and assumptions

| Ref | Source |
|---|---|
| A1 | Artefact 1: reported email and service desk notes (SD-2026-4417) |
| A2 | Artefact 2: Sentinel incident 2026-W2D1-0093, sign-ins and Conditional Access evaluation |
| A3 | Artefact 3: Unified Audit Log extract for `r.oduya@finserve.example` |
| E1, E4 | `02-ARCHITECTURE/01-Network-Diagram.md`, `04-Data-Flow.md` (as cited in `Detection-Surface.md`) |
| E7 | `04-SOC/Logs/Log-Source-Inventory.md` |
| E8 | `04-SOC/Alerts/Analytics-Rules.md` |
| E9 | `04-SOC/Alerts/Alert-Summary-30-Days.md` |
| E10 | `04-SOC/Incident-Tickets/Incident-Log-2025.md` |
| E11 | `04-SOC/Threat-Intel/Threat-Profile-2025.md` |
| E12 | `04-SOC/IOCs/IOC-Register.md` |

| # | Assumption or caveat |
|---|---|
| T1 | All times are UTC, following the 04-SOC convention. The service desk times (08:31, 08:47) are treated as UTC. If they were UK local time (BST) the report at 08:31 would precede the email's arrival at 07:52 UTC, which is impossible. |
| T2 | The 07:41:02 and 09:31:08 sign-ins come from the corporate ExpressRoute range and are treated as Rachel's own sessions [A]. |
| T3 | The link in the artefact is wrapped in a Google redirect, a side effect of how the email was forwarded. The real target is `finserve-co[.]example/portal/sso/auth?ref=settle-q4&rd=sharepoint`. It has not been visited and should not be opened from a corporate device. |
| T4 | The service desk note reads: "Nadia says she sent it?" This is ambiguous. It may mean the email claims to be from Nadia, or that Nadia told the analyst she sent it. The headers say she did not (Section 3). **If Nadia herself confirms sending it, her account is also compromised and the scope doubles.** Checking this is step 1 of containment. |

## 3. Timeline (UTC)

| Time | Event | Source | Basis |
|---|---|---|---|
| 07:41:02 | `r.oduya` signs in to Exchange Online from 81.2.69.144 (London, corporate ExpressRoute). MFA "satisfied, claim in token". | A2 | **[F]**. Treated as the genuine user starting work **[A]**. |
| 07:52:09 | Email dated. Display name "Nadia Ferreira", From `n.ferreira@finserve.example`, Reply-To `n.ferreira@finserve-co[.]example`. | A1 | **[F]** |
| 07:52:11 | Exchange Online receives it from 203.0.113.87 (an outbound mail service, not FinServe infrastructure). SPF fail, DKIM none, DMARC fail with `action=none`. Delivered to six Finance Operations recipients. | A1 | **[F]** |
| 07:52 to 07:58 | Rachel opens the email, follows the link and signs in, including MFA, on a page the attacker controls. | none direct | **[A]**. Basis: her "done" reply at 07:58 and an MFA claim replayed at 07:59:44. No sign-in row for this step is in A2 (see Q1). |
| 07:58 | Rachel replies to the sender: "done". | A1 (ticket) | **[F]** that the reply was sent. **[A]** that it went to the Reply-To address, as replies do by default. Message trace Q3 confirms. |
| 07:59:44 | First sign-in from 45.83.220.61 (AS205544, hosting, "Manchester"), Exchange Online, success, MFA claim in token. 1 minute 44 seconds after the reply. | A2 | **[F]**. Token replay is **[A]**. |
| 08:02:17 | Microsoft Graph sign-in, same IP. | A2 | **[F]** |
| 08:02:44 | `New-InboxRule`, name ".", subject or body contains "meridian;settlement;reconciliation", move to "RSS Subscriptions", mark as read. Exactly 3 minutes 00 seconds after the first sign-in. | A3 | **[F]**. The regular gap suggests a prepared playbook **[A]**. |
| 08:05:19 | `MailItemsAccessed`, Inbox, via Graph. | A3 | **[F]**. Number of items **[U]**. |
| 08:09:03 | `MailItemsAccessed`, "Settlement Ops (shared)", via Graph. | A3 | **[F]**. Number of items **[U]**. |
| 08:14:55 | SharePoint Online sign-in, same IP. `FileAccessed` on `Settlement runbook v4.docx`, site `/sites/FinanceOps`. | A2, A3 | **[F]** |
| 08:16:30 | `FileDownloaded`: `Settlement runbook v4.docx`. | A3 | **[F]** |
| 08:22:41 | `FileAccessed`: `DR-SLO access notes.txt`. | A3 | **[F]** |
| 08:23:02 | `FileDownloaded`: `DR-SLO access notes.txt`. Last attacker event in the extract. Observed activity: 23 minutes 18 seconds. | A3 | **[F]** |
| 08:31 | A Finance Operations analyst forwards the email to phishing@. | A1 (ticket) | **[F]** (T1) |
| 08:47 | Sentinel raises 2026-W2D1-0093, "Atypical travel", Medium, status New. 47 minutes 16 seconds after the first malicious sign-in. | A2 | **[F]** |
| 09:31:08 | Sign-in to Exchange Online from 81.2.69.144 (London, corporate). | A2 | **[F]**. Rachel's own session **[A]** (T2). |
| After 08:23:02 | Attacker activity. | none | **[U]**. See Section 5.3. |

> **Update (Inject 06):** activity from the same address after 08:23:02 is now evidenced on the DC-SLO host, from 17 October. Activity in M365 after 08:23:02 is still unknown. The full week is in Section 15.

**What the timeline shows**

- **The compromise began before the alert's "first activity".** Sentinel dates the incident from 07:59:44. The credential and MFA hand-over happened between 07:52 and 07:58 **[A]**, so the attacker held access roughly 49 to 55 minutes before the incident existed.
- **A person beat the machine.** The phishing report (08:31) came 16 minutes before the Sentinel incident (08:47). Nothing links the phishing@ mailbox to Sentinel, so the report did not create or enrich an incident. This matches the pattern in the incident log: 8 of 12 recorded incidents were found by a person (E10 §5).
- **Nobody was due to see it.** 08:47 is 13 minutes before the documented working day starts at 09:00 (E9 §4). The incident was still New when the artefacts were pulled.
- **The attacker knew the vocabulary before reading the mail.** The rule (08:02:44) was created before the first inbox access (08:05:19). "Meridian" and "settlement" are in the phish, but "reconciliation" is not. This is consistent with prior knowledge of FinServe's process **[A, low confidence]**, because "reconciliation" is also a generic finance word.
- **The extract is incomplete.** The sign-in list runs to 09:31 but shows only five rows, and audit events stop at 08:23:02. Either the attacker stopped, or the extracts are filtered. Q1 and Q8 settle it **[U]**.

## 4. How the control stack was defeated

The inject says six controls were in the path. The artefacts evidence six: email authentication, and the five Conditional Access policies that were evaluated. The seventh, the Atypical travel rule, is detective and is covered in Section 9.

### 4.1 The six controls

| # | Control | What it did | Why it did not stop the attack | Basis |
|---|---|---|---|---|
| 1 | **Email authentication** (SPF, DKIM, DMARC) | SPF failed (203.0.113.87 is not authorised for `finserve.example`). DKIM absent. DMARC failed. It detected the spoof and recorded it. | `action=none` means no enforcement. This is consistent with a published DMARC policy of `p=none`, so failing mail is still delivered. SEC-2025-03 action 2 (move to quarantine then reject) is still open (E10 §4). | **[F]** headers. **[A]** that the policy is `p=none` (check with Q10). |
| 2 | **CA Policy 1: require MFA for all users** | Not applied, because an MFA claim was already in the token. | MFA was not bypassed. It was inherited. Rachel completed MFA on the attacker's page and the attacker replayed the resulting token. The 07:41 and 09:31 legitimate sign-ins show the same wording, so the string alone cannot separate good from bad. | **[F]** claim in token. **[A]** adversary-in-the-middle. |
| 3 | **CA Policy 3: block legacy authentication** | Not applied: modern authentication. | It was never in the path. The attacker used Exchange Online, Graph and SharePoint over modern protocols. This control stops a different attack. | **[F]** |
| 4 | **CA Policy 5: block access from outside UK, IE and ES** | Not applied: the IP geolocates to GB. | The control is only as good as IP geolocation. The attacker's infrastructure is UK-hosted. Deliberate or not, the policy never fired. | **[F]** result. **[A]** intent. |
| 5 | **CA Policy 7: session controls for unmanaged devices** | Applied (app-enforced restrictions). Two files were downloaded anyway. | App-enforced restrictions are a signal to the app. They only work if SharePoint and Exchange are configured to restrict unmanaged access, and they do not cover API access. Both mailbox reads were through Graph. | **[F]** applied and downloads. **[A]** cause. Check the SharePoint unmanaged-device setting and the `UserAgent` and `IsManagedDevice` fields on the download events (Q8). |
| 6 | **CA Policy 9: high sign-in risk, require password change** | Not applied: risk "low". | A valid token replayed from a new IP generates few of the classic risk signals. Whether Entra ID Protection's token-based detections ("attacker in the middle", if licensed) are available for Rachel is unknown. | **[F]** result. **[U]** licensing. |

### 4.2 Controls the artefacts are silent on

These are expected in the path and would normally have helped. None is evidenced either way. Each is a question for the mentor (Section 11).

- **Anti-phishing impersonation protection** for "Nadia Ferreira". SEC-2025-03 action 1 (extend protection beyond the executive list) is open, so I assess she was not covered **[A]**.
- **Safe Links** detonation or blocking of `finserve-co[.]example`. The threat profile relies on it for credential phishing (E11 §5), but the domain was probably new and unknown **[A]**.
- **External sender banner.** It may not have applied to a spoofed internal address **[U]**.
- **Compliant-device or phishing-resistant MFA requirement** for Exchange and SharePoint. Evidently not enforced for this session.

### 4.3 What the pattern says

1. **Five of six controls worked as configured, and the configuration let the attack through.** DMARC was set to observe. The session control was a signal, not a block. Geo-blocking and the legacy-auth block were not relevant. MFA was satisfied. Risk scoring saw nothing unusual. The only control that acted on the content of the attack was the detective rule, 47 minutes late.
2. **FinServe's own documents predicted this.** The threat profile describes adversary-in-the-middle kits that capture session tokens and defeat MFA, then records "None" under gaps and links no detection to it (E11 §1, §6). The analytics rules document confirms no mapping from threats to rules exists (E8 §5).
3. **This is a repeat.** SEC-2025-03 was an invoice-themed phish against Finance Operations with one credential entry and a reset within four hours. Its action 4 asked whether a password reset ends an attacker's session, and was recorded and never answered (E10 §4). That question matters again here: a password reset alone is not a safe way to evict this attacker (Section 7).
4. **The other open action matters too.** SEC-2024-04 (BEC attempt against Finance, July 2024) raised a review of out-of-band verification for payment authorisation, still open (E10 §3).

## 5. Scope

### 5.1 Established (evidence in the artefacts)

- Sessions from 45.83.220.61 reached Exchange Online, Microsoft Graph and SharePoint Online as `r.oduya` (A2).
- An inbox rule named "." was created at 08:02:44. Messages mentioning meridian, settlement or reconciliation are moved to "RSS Subscriptions" and marked read (A3). **The rule is server-side. It keeps working after the account is blocked** and is hiding related mail from Rachel until it is disabled.
- Her Inbox and the "Settlement Ops (shared)" mailbox were accessed through Graph (A3). The shared mailbox probably holds settlement correspondence **[A]**. Whether it is the one FinRecon reads is **[U]**.
- Two files were downloaded: `Settlement runbook v4.docx` and `DR-SLO access notes.txt` (A3).

### 5.2 Assessed as likely

- The credentials and MFA were captured by an adversary-in-the-middle page **[A]**. Basis: the reply-then-replay timing, the MFA claim, the lookalike Reply-To domain and the `rd=sharepoint` redirect parameter. The alternative, token theft from Rachel's device by malware, is less likely because there is no endpoint evidence.
- The goal is settlement-process reconnaissance, leading to payment or settlement fraud **[A]**. Basis: the files taken, the rule keywords, the settlement-themed pretext and the threat profile rating BEC against Finance as High (E11 §2).
- `DR-SLO access notes.txt` contains access details for the Slough estate **[A]**. Basis: the name only. Unverified. Treated as containing credentials until someone who has read it says otherwise.
- Nadia's account is **not** compromised **[A, moderate confidence]**. Basis: SPF fail from an external IP and a lookalike Reply-To. See T4.

> **Revised (Inject 06):** the second bullet, "the goal is settlement-process reconnaissance, leading to payment or settlement fraud", is widened. The host reads (settlement archive, delivery configuration, a UAT refresh script) and the connection to `sqldb-uat` point at least as much to credential and data collection. I cannot rank the aims (Section 26).

### 5.3 Cannot rule out

This is the part that matters most. Each row says why the question cannot be answered and what kind of gap stops it.

| # | What we cannot rule out | Why | Gap type | How to settle |
|---|---|---|---|---|
| 1 | **Attacker activity after 08:23:02**, or activity not in the three artefacts | UAL events stop at 08:23:02. Only five sign-in rows are shown. Non-interactive sign-ins are collected (E7 §1) but not in the extract. | Query not yet run | Q1, Q8. If non-interactive sign-ins from 45.83.220.61 continue until the revocation, the attacker was live throughout. |
| 2 | **How many mail items were read**, and which | Two `MailItemsAccessed` events do not show a count. These records can be aggregated. | Audit granularity | Q8 (full `AuditData`). |
| 3 | **Use of the DR-SLO notes against the Slough estate** (the SFTP server and the other DC-SLO workloads) | The SFTP server logs locally for 30 days and has no forwarder. The backup appliance and the other workloads are unlogged or unidentified (E7 §3). Fortigate flows are partial. | **Absent telemetry.** Cannot be answered from Sentinel at all. | Q9: the server's local auth log, copied off now. See Coverage-Gaps G3. |
| 4 | **An earlier compromise** (the "reconciliation" vocabulary suggests prior knowledge) | Workspace sign-in logs reach back 60 days, Entra 30 days. The UAL reaches back 90 or 180 days (E7 §4; E3 §7 via `Detection-Surface.md`). | **Expired retention** | Q2 for what the 60 days show. Anything older is gone. |
| 5 | **Other recipients compromised** | Five other people received it. Four deleted it, which does not tell us whether they clicked. Clicks from phones, remote workers and branches do not pass through the logged firewalls. Branch firewall logs are local for 14 days (E7 §3). | **Absent telemetry** and query not yet run | Q2, Q3, Q4, Q5, and a phone call to each recipient. |
| 6 | **Persistence**: a new MFA method, an OAuth consent, mailbox delegates, or forwarding set through the API | Nothing in the artefacts covers directory or mailbox configuration changes. | Query not yet run | Q6, Q7. |
| 7 | **Mail sent from Rachel's account** (internal phishing, fraudulent requests) | No `Send` events appear, but the extract may be filtered. | Query not yet run | Q3, Q8. |
| 8 | **A changed settlement instruction, or contact with Meridian Trust** | Not visible in any log we hold. | A business-process gap, not telemetry | Phone Finance Operations and Meridian Trust through a known number. |

> **Update (Inject 06):** row 3 of the table above is superseded in part. Use of Slough access is now **observed** from 17 October (Section 15). Row 4's horizon is refined per surface in Section 20.

## 6. Severity

> **Superseded by Inject 06 (Section 21): the severity is now Critical.** This section is kept as written for Inject 04. **Update (Inject 07):** reconfirmed as Critical on 21 October (Section 32.6).

**High, provisional.** Sentinel's rating of Medium reflects only the location anomaly.

**Why High**

- Confirmed account takeover of a Finance Operations user, with MFA defeated rather than avoided.
- Hands-on activity: a concealment rule within three minutes, then targeted mail and file access.
- Two files removed, one of which may open a path into the legacy Slough estate. That path has no Sentinel telemetry, and its credential has not changed since 2019 (E4 §4 as cited in `Coverage-Gaps.md` G3).
- It touches the settlement process, and the threat profile rates BEC against Finance as High.
- The scope is open (Section 5.3), and the same weaknesses were recorded in 2025 and not closed.

**Why not Critical yet.** There is no evidence so far of customer data loss, a payment change, a second compromised account or use of the Slough access.

> **Withdrawn (Inject 06):** the phrase "or use of the Slough access" is contradicted by the host log (Section 15). One of the Critical triggers named below, "the SFTP logs show an unfamiliar login", is met.

**What would raise it to Critical:** the DR-SLO notes contain working credentials or the SFTP logs show an unfamiliar login; any second account compromised; any changed settlement instruction or payment.

**What would lower it to Medium:** both files confirmed non-sensitive, no activity after 08:23:02, no other victims, no persistence.

**Notification.** Whether personal data was exposed is unknown, because nobody has reviewed the files. The GRC track and the CISO decide on notification obligations. I flag it, I do not decide it.

## 7. Containment and eradication

### 7.1 Order of work

Three kinds of action appear below.

- **STOP**: reduces ongoing harm.
- **PRESERVE**: protects evidence that would otherwise change or expire.
- **VERIFY**: finds out something that changes the next step.

Where a STOP action would destroy evidence, I take the version that keeps it (disable rather than delete, soft delete rather than purge), or I preserve first when the delay is a few minutes. Section 7.3 lists every conflict.

### 7.2 The first hour

| When | Action | Type | Notes |
|---|---|---|---|
| T+0 | **Tell the CISO (Priya Raman) and Marcus Ifill now.** Do not wait for the report. | STOP | Escalation is not saved for the presentation. |
| T+0 | **Phone Nadia Ferreira** on a known number. Confirm she did not send the email. Ask Finance Operations to action nothing that arrives on this thread. | VERIFY | Settles T4. |
| T+0 to 5 | **Revoke all sessions for `r.oduya` and block sign-in** (disable the account). Do not rely on a password reset alone. | STOP | `Revoke-MgUserSignInSession`, then set `AccountEnabled` to false. Logs are unaffected. See 7.3, row 2. |
| T+0 to 5 | **Phone Rachel.** She is a victim, so keep it non-blaming. Ask what she clicked, whether she entered a password and approved an MFA prompt, which device she used, and ask her not to touch the mailbox. | VERIFY | Her account of the 07:52 to 07:58 gap fills the main hole in the timeline. |
| T+3 to 10 (in parallel) | **Snapshot the evidence.** Export the output of Q1, Q7 and Q8. Export `Get-InboxRule -IncludeHidden` in full. Export her registered MFA methods. Ask the reporting analyst to **forward the original email as an attachment**, so the headers are intact. Place a hold on Rachel's mailbox. | PRESERVE | Cloud logs persist, so this takes minutes, not hours. |
| T+5 to 10 | **Disable the inbox rule "." (do not delete).** | STOP | Blocking the account does not stop a server-side rule. `Disable-InboxRule` keeps the artefact. |
| T+10 | **Block the lure:** `finserve-co[.]example` (Tenant Allow/Block List, Defender for Endpoint indicator, Fortigate web filter) and the IPs 45.83.220.61 and 203.0.113.87. **Soft-delete** the email from the other five mailboxes once the message IDs are recorded. | STOP | Blocking a domain is a stop-gap. Attackers change domains. |
| T+10 to 30 | **Find other victims** with Q2, Q3, Q4 and Q5. Apply the revoke and block step to each. Phone the five other recipients, including the four who deleted the email. | VERIFY, STOP | Branch, remote and mobile clicks are invisible to the firewalls. People are the only source. |
| T+10 to 30 | **Remove persistence** found by Q6 and Q7: unknown MFA methods, OAuth consents, delegates, forwarding. **Then** reset the password (in AD, allowing for sync) and have Rachel re-register MFA in person. | STOP | Order matters (7.3, row 6). |
| T+10 to 30 | **Copy the DC-SLO SFTP server's local logs off the box** (`auth.log` and the sftp-server logs, 30 days on device, no forwarder), with hashes. Review for logins since 08:23 (Q9). | PRESERVE, VERIFY | Done before any credential change. |
| T+10 to 30 | **Ask what is in the two files** (Nadia's team, and the infrastructure team that holds Slough knowledge). Do it by phone, not through the shared mailbox. | VERIFY | Decides Critical or High. |
| T+30 to 60 | **CISO decision: rotate the static SFTP credential.** My recommendation is to rotate today, in a window before the nightly run (23:30 extract, 00:15 delivery, E4 §4 as cited in `Detection-Backlog.md` DET-06), coordinated with Meridian Trust and with a tested fallback. Until then, review the server's auth log by hand at intervals. | STOP | The conflict is in 7.3, row 5. |
| T+30 to 60 | **Check with Meridian Trust** through a known number that no revised schedule was sent or acknowledged from FinServe. Hold any change to settlement instructions until verified. | VERIFY, STOP | Settlement fraud is the likely objective (5.2). |
| T+30 to 60 | **Record the indicators** (Section 10). Warn Finance Operations briefly about the lure, through a channel the attacker never held. Keep a time-stamped decision log. | PRESERVE | The IOC register is not connected to Sentinel (E12 §1). Applying anything is manual. |

### 7.3 Where stopping the harm and keeping the evidence conflict

| # | Conflict | Choice | What it costs |
|---|---|---|---|
| 1 | **Watch the attacker to learn more** or **evict now** | Evict now. The attacker already holds files that may open a path into Slough, and every extra minute adds exposure. The cloud logs persist for reconstruction. | We lose a live view of the attacker's next moves. Blocked sign-in attempts after revocation become useful evidence themselves. |
| 2 | **Reset the password** or **revoke sessions** | Revoke sessions and block sign-in first. A password reset alone may leave an issued token usable for a while, and the environment is hybrid, so a reset in AD only reaches Entra after sync. This answers the open SEC-2025-03 action 4 in practice: **do not rely on a reset alone**. | None. Nothing is deleted. |
| 3 | **Delete the inbox rule** or **disable it** | Disable. Server-side rules run whatever the account state, so it must be stopped, but the artefact is evidence of attacker intent. | Slight clutter in the mailbox until closure. |
| 4 | **Purge the phish from mailboxes** or **keep a copy** | Record message IDs, preserve the original, then soft-delete. A hard purge destroys what the PIR and any regulator would want. | A short window in which the email is recoverable by users from Recoverable Items. |
| 5 | **Rotate the SFTP credential now** or **protect tonight's settlement run** | Copy the local logs first. Then rotate before 23:30, coordinated with Meridian Trust and Finance Operations. This is a **CISO decision**. | A bad rotation fails settlement. A delayed rotation leaves a possibly exposed credential live for hours. |
| 6 | **Reset the password first** or **remove the attacker's MFA method first** | Remove persistence first, then reset. Resetting first and leaving a registered attacker authenticator in place leaves a path back in. | A delay of minutes before Rachel can work again. |

> **Superseded by Inject 06 (Section 22):** the last CISO-decision row of 7.2 and row 5 of 7.3 recommended rotating the static SFTP credential before tonight's run. Meridian has since suspended the account and tonight will not deliver. The question is now how and when the account comes back, and the old credential is not reinstated. The M365 actions in 7.2 stand. Whether they were carried out is not stated in any artefact (Section 22, C-12).

### 7.4 After the first hour (eradication)

- Rotate everything the two files reveal. Treat the DC-SLO credential as exposed until proven otherwise.
- Move DMARC to quarantine, then reject, after a check for legitimate senders (SEC-2025-03 action 2, now overdue).
- Extend impersonation protection to Finance Operations leads (SEC-2025-03 action 1).
- For Finance Operations and administrators: require a compliant device for Exchange and SharePoint, move towards phishing-resistant MFA, and configure the SharePoint unmanaged-device restriction so that Policy 7 actually blocks downloads.
- Hold the post-incident review. FinServe policy requires one for Medium or above, and SEC-2024-07 and SEC-2025-02 had none (E10 §3). Record the answer to SEC-2025-03 action 4.
- Forward the DC-SLO SFTP server logs to Sentinel (Coverage-Gaps G3), so the next question like Section 5.3 row 3 has an answer.

## 8. Queries I would run, and what I expect

None has been run. Table and column names are as I understand the schemas and must be checked in the workspace. All are read-only.

**Q1. Everything Rachel's account did, interactive and non-interactive (Sentinel)**

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "r.oduya@finserve.example"
| project TimeGenerated, Table = Type, AppDisplayName, IPAddress, AutonomousSystemNumber,
          ResultType, UserAgent, ClientAppUsed, AuthenticationRequirement, ConditionalAccessStatus, SessionId
| sort by TimeGenerated asc
```

*Expect:* the five listed rows, plus an interactive sign-in between about 07:52 and 07:58 where MFA was actually performed, probably from unfamiliar infrastructure and with an unusual `UserAgent`. Also non-interactive rows from 45.83.220.61 continuing until the revocation. If they continue past 08:23, the attacker was active throughout.

**Q2. Anyone else seen on the attacker's network (Sentinel)**

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(60d)
| where IPAddress == "45.83.220.61" or AutonomousSystemNumber has "205544"
| summarize Users = make_set(UserPrincipalName), First = min(TimeGenerated), Last = max(TimeGenerated), Events = count()
    by IPAddress, AutonomousSystemNumber
```

*Expect:* Rachel only, first seen about 07:59. Any other user is another victim. An earlier `First` date points to earlier reconnaissance (Section 5.3, row 4). Retention caps the answer at 60 days.

**Q3. Who received it, and who replied to the lookalike domain (Exchange message trace)**

```powershell
Get-MessageTraceV2 -SenderAddress n.ferreira@finserve.example -StartDate <W2D1 07:00Z> -EndDate <now>
Get-MessageTraceV2 -RecipientAddress "*@finserve-co.example" -StartDate <W2D1 07:00Z> -EndDate <now>
```

*Expect:* six deliveries from 203.0.113.87 at about 07:52, and one outbound message from `r.oduya` to `finserve-co[.]example` at about 07:58. Any other outbound message to that domain is another person who replied.

**Q4. Who clicked (Defender advanced hunting, not Sentinel)**

```kql
UrlClickEvents
| where Timestamp > ago(2d)
| where Url has "finserve-co.example"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
```

*Expect:* a click row for `r.oduya` at about 07:5x, and rows for any others. This requires Safe Links click tracking to be on **[U]**. The Defender XDR connector appears to carry alerts only (E7 §1), so this table is probably not in the workspace **[A]**.

**Q5. Who visited from the logged network (Sentinel)**

```kql
union AZFWApplicationRule, Syslog
| where TimeGenerated > ago(2d)
| where Fqdn has "finserve-co.example" or SyslogMessage has "finserve-co.example"
```

*Expect:* hits only for traffic that crossed Azure Firewall or the HQ and DC-SLO Fortigates. Phones, remote workers on split-tunnel VPN and branch users leave no row, so an empty result proves little.

**Q6. Mailbox configuration (Exchange Online PowerShell)**

```powershell
Get-InboxRule -Mailbox r.oduya@finserve.example -IncludeHidden | fl Name,Enabled,Description,MoveToFolder,MarkAsRead,SubjectOrBodyContainsWords
Get-Mailbox r.oduya@finserve.example | fl ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
Get-MailboxPermission -Identity r.oduya@finserve.example | Where-Object { $_.User -notlike "NT AUTHORITY*" }
```

*Expect:* one rule named "." and nothing else, no forwarding, no new delegates. Anything else is persistence.

**Q7. Directory changes by or about Rachel (Sentinel)**

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where tostring(InitiatedBy) has "r.oduya@finserve.example" or tostring(TargetResources) has "r.oduya@finserve.example"
| where OperationName has_any ("security info", "authentication method", "Consent to application",
        "Add service principal", "Add delegated permission grant", "Reset password", "Change password")
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
```

*Expect:* nothing after 07:58, ideally. A "registered security info" event from 45.83.220.61 means the attacker added an MFA method and a reset would not evict them.

**Q8. Full audit detail for the account (Unified Audit Log)**

```powershell
Search-UnifiedAuditLog -UserIds r.oduya@finserve.example -StartDate <W2D1 07:30Z> -EndDate <now> -ResultSize 5000 |
  Select-Object CreationDate, Operations, AuditData
```

*Expect:* for the two downloads, `ClientIP` 45.83.220.61, a `UserAgent` that is not the corporate browser and `IsManagedDevice` false. Also any `Send`, `SearchQueryPerformed` and `FileSyncDownloaded` events after 08:23, which would show what else the attacker looked for.

**Q9. The Slough settlement server (shell on the server, plus Sentinel)**

```bash
# on the DC-SLO SFTP server, after copying the logs off the box
grep -E "Accepted|Failed" /var/log/auth.log
```

```kql
Syslog
| where TimeGenerated > ago(2d)
| where Computer has "FGT-SLO"
| where SyslogMessage has "45.83.220.61"
```

*Expect:* only the nightly delivery script's logins, and no Fortigate flows involving the attacker's IP. Even a clean result does not prove the credential was not used from other infrastructure (Section 5.3, row 3).

> **Contradicted by Inject 06:** the host log shows eleven successful logins by `finserve_settle` from 45.83.220.61 (two shown, nine described). Those were not the nightly delivery script's logins. Whether any Fortigate flow involves the address is not yet known (Q14).

**Q10. The DMARC policy (any machine)**

```
nslookup -type=TXT _dmarc.finserve.example
```

*Expect:* `p=none`, confirming Section 4.1, row 1.

**Q11. How late does the data arrive (Sentinel)**

```kql
union SigninLogs, OfficeActivity
| where TimeGenerated > ago(7d)
| extend DelayMinutes = datetime_diff("minute", ingestion_time(), TimeGenerated)
| summarize P50 = percentile(DelayMinutes, 50), P95 = percentile(DelayMinutes, 95) by Type
```

*Expect:* sign-in delays in the low minutes and Office activity delays noticeably longer. This is **unmeasured** in this workspace and decides how much sooner any detection could have fired (Section 9).

## 9. Detection gap

**What fired:** the Microsoft built-in "Atypical travel" rule, at 08:47, 47 minutes 16 seconds after the first malicious sign-in. It flagged **where** the session came from. It said nothing about **what** the session did: the token replay, the concealment rule or the two downloads. The incident as raised held none of that. It also looked like the other 70 "Atypical travel" incidents of the month, of which 44 were closed as benign positive and 1 was investigated (E9 §2), so it risked being closed the same way.

**What mattered:** the post-compromise behaviour. The inbox rule at 08:02:44 is the first persistent attacker action, and the sign-in at 07:59:44 is the first observable attacker event.

| Signal | Earliest it could fire | Collected today? | Detection |
|---|---|---|---|
| Spoofed internal sender with a lookalike Reply-To | 07:52 (delivery) | **No.** Email events are not in the workspace, as far as `E7` shows. | Telemetry first. Not written. |
| URL click on a newly seen domain | about 07:55 | **No** (Q4 table not in workspace) | Telemetry first. Not written. |
| Unmanaged device and new IP, MFA from a token claim, finance user | 07:59:44 plus ingestion delay | **Yes**, `SigninLogs` (E7 §1) | **DET-11** |
| Concealing inbox rule | 08:02:44 plus ingestion delay | **Yes**, `OfficeActivity` (E7 §1) | **DET-10** |

Both detections are written in `Detection-Backlog.md`, Section 8. If ingestion delays are in the low minutes (Q11), DET-11 could have raised an alert roughly 30 to 40 minutes before 08:47. If Office activity arrives 30 minutes or more late, DET-10 would only marginally beat the actual detection, which is why DET-11 is paired with it. **These timings are estimates and rest on the unmeasured delays in Q11.**

DET-10 supersedes the move-rule branch of the existing DET-09 with far higher fidelity, and this incident is the evidence for ranking the pair above the Azure Activity detections.

## 10. Indicators

None has been enriched or looked up. They are not applied to any detection. Applying them means a manual act (E12 §1).

| Indicator | Type | Context |
|---|---|---|
| `finserve-co[.]example` | Domain | Lookalike domain, phishing page and Reply-To |
| `n.ferreira@finserve-co[.]example` | Email | Reply-To address |
| 45.83.220.61 (AS205544) | IPv4 | Sign-in source for the replayed session |
| 203.0.113.87 | IPv4 | Sending IP of the phishing email |
| Inbox rule named ".", moving mail mentioning meridian, settlement or reconciliation to "RSS Subscriptions" | Behaviour | Concealment rule |
| 45.83.220.61 (inbound to `sftp-slo`, W2 D6 to W3 D1) | IPv4 | Source of password logins as `finserve_settle` (Inject 06). Also named by Meridian Trust for its own platform. |
| Read requests for `/settlement/archive/SETL-2026W2D5.csv`, `SETL-2026W2D4.csv`, `/opt/finrecon/conf/deliver.cfg`, `/opt/finrecon/conf/refresh_uat.ps1` by those sessions | Behaviour | Collection on the host. Requests, not confirmed transfers. |
| Flows from 172.20.14.30 to 10.30.2.14:1433, W2 D7 04:11:09 to 04:14:38, rule `CHG-2025-0132-dev-fileshare` | Behaviour | Permitted connection to `sqldb-uat`. 172.20.14.30 and 10.30.2.14 are FinServe assets, **not** indicators to block. |

## 11. Questions for FinServe (through the mentor)

| # | Question | Why it matters |
|---|---|---|
| 1 | Did Nadia Ferreira send this, or confirm sending it? | Settles T4. If yes, a second account is compromised. |
| 2 | What do `Settlement runbook v4.docx` and `DR-SLO access notes.txt` contain? Do they hold credentials? | Decides High or Critical. |
| 3 | Who else can read `/sites/FinanceOps` and "Settlement Ops (shared)"? Is that the mailbox FinRecon reads? | Sets the real exposure of the files and the mailbox. |
| 4 | Is the SharePoint unmanaged-device restriction configured, or is Policy 7 only a signal? | Explains why the downloads worked. |
| 5 | Is Entra ID Protection licensed for token-based risk detections for Finance Operations? Is Safe Links click tracking on? | Decides which detections can use those sources. |
| 6 | Is the SOC authorised to disable accounts and block domains without CISO approval during an incident? What is FinServe's own severity scale? | Controls who may act in the first hour. |
| 7 | Which team holds the rotation procedure for the DC-SLO SFTP credential and how is Meridian Trust notified of a change? | Needed for the decision in 7.3, row 5. |

---

# Part 2. Inject 06 update: the Slough settlement server

**Revised W3 D1 (Monday 19 October 2026), after Inject 06.** Sections 12 to 31 are new. Sections 12 to 25 follow the order the Inject 06 brief asks for, with Sections 13 and 14 carrying the evidence and the linkage reasoning that Section 12 summarises. Sections 26 to 31 are supporting. Sections 1 to 11 stand as written for Inject 04, except where a note marked **Superseded** or **Update** points here (index in Section 26).

## 12. Incident Overview

**Position: one incident, not two.** Inject 06 shows the address that took over Rachel Oduya's session on W2 D1 (45.83.220.61) logging in to the DC-SLO settlement SFTP server as `finserve_settle` from W2 D6, and Meridian Trust reporting the same address against its own SFTP platform. I assess this as the same intrusion continued, with **high confidence that it should be handled as one incident** and **moderate to high confidence that it is the same operator** **[A]** (Section 14). The halves are joined by the address, the target and the sequence. No artefact shows how the actor got from a stolen M365 session to a working Slough credential and a network path to the host (Section 16, steps P4 and P5).

### 12.1 The original incident (Inject 04)

On Monday 12 October a Finance Operations user, Rachel Oduya (`r.oduya`), received a spoofed "Nadia Ferreira" email and, on the evidence, signed in on an attacker-controlled page. About 100 seconds after her "done" reply, a session using her token appeared from 45.83.220.61, a hosting network in Manchester. Within 23 minutes it had created a concealing inbox rule, read her inbox and the "Settlement Ops (shared)" mailbox, and downloaded two files: `Settlement runbook v4.docx` and `DR-SLO access notes.txt` (A1 to A3; Sections 1 and 3). Sentinel rated the incident Medium. I rated it **High, provisional**, rising to **Critical** if the notes held working access details or the SFTP logs showed an unfamiliar login (Section 6).

### 12.2 The escalation (Inject 06)

On Monday 19 October at 07:12 Meridian Trust reported eleven authentications against `finserve_settle` on its SFTP platform from the same address, nine successful, outside the delivery window and used to list and retrieve (I6-A1). It suspended the account, so tonight's settlement will not deliver. The DC-SLO host's local log shows two password logins to `sftp-slo` from that address, and read requests for two settlement archive files and for two files in `/opt/finrecon/conf` (I6-A2). Azure Firewall shows three permitted connections from the host to `sqldb-uat` at 04:11 to 04:14 (I6-A3). The SQL audit query returns nothing (I6-A3). Marcus Ifill says he cannot see what the connection did, and cannot say whether this began at the weekend or earlier (I6-A4).

### 12.3 Are the events linked?

| Question | Assessment | Confidence | Basis in one line |
|---|---|---|---|
| Should this be one incident record? | **Yes. Merge.** | **High** | The same address appears in three artefacts (L1), against the same business target (L2), in an order a single operator would follow (L4). |
| Is the Slough activity by the same operator as the M365 activity? | Probably | **Moderate to high** **[A]** | Seven strands, L1 to L7, none conclusive alone (14.1). Only L1 is the address itself. |
| Did the M365 downloads supply the Slough credential? | Possible and unproven | **[H]**, not rated | Nothing joins steps P3 and P6 (Section 16). |

**Limits.** An address is not an actor: it sits in a hosting network and five days separate its two uses (14.3). The host extract is hand-retrieved, shows two of eleven sessions and has no hash (13.3). No artefact shows how the actor obtained a working credential or reached the host (Section 16, P4 and P5). The full reasoning, including the alternatives I considered and what would make me split the incident, is in Section 14.

### 12.4 Where this stands

**Severity: Critical.** Section 6 set the trigger: "the SFTP logs show an unfamiliar login". They do. Section 6's statement that there was no evidence of use of the Slough access is withdrawn (Section 26).

**What is observed** (facts, with their limits)

- Password logins to `finserve_settle` on the host `sftp-slo` (172.20.14.30) from 45.83.220.61. Two sessions are shown (W2 D6 22:04:11 to 22:19:07 and W2 D7 03:51:44 to 04:02:55). Nine more are described and not shown (I6-A2).
- Read requests for two files in `/settlement/archive` (W2 D6) and for `deliver.cfg` and `refresh_uat.ps1` in `/opt/finrecon/conf` (W2 D7). These are requests recorded in a log. The extract does not show that any transfer completed.
- Three Azure Firewall **Allow** records from the host to `sqldb-uat` port 1433 at W2 D7 04:11:09, 04:11:12 and 04:14:38, which is 8 minutes 14 seconds after the second session ended (I6-A3). They show that the network permitted a connection. They do not show a database login, a query or any data returned.
- Meridian Trust reports eleven authentications against `finserve_settle` on its platform, nine successful, used to list and retrieve, from the same address. It has suspended the account (I6-A1). This is a third-party statement, not a log we hold.

**Five questions that decide the outcome**

1. **How did the actor get a working credential and a route to the host?** Nothing evidences it. This is the first unsupported transition in the path (Section 16).
2. **What did the 04:11 connection do, and who started it?** There is no SQL-side record in Sentinel. Whether one exists elsewhere is unknown (Section 19, row 1).
3. **What is in the four files read on the host and the two downloaded from SharePoint?** One of them, `deliver.cfg`, is documented as holding the static Meridian delivery credential (E4 §4). The others are described by name only, and I have not inferred their contents.
4. **Was the actor on the host before W2 D6 22:04:11?** The host's full `auth.log` can answer this from its first line (mid-September to early October, label unresolved). Nothing FinServe holds answers it for earlier dates (Section 20).
5. **Did anything leave the estate?** No exfiltration is confirmed anywhere. Several routes cannot be seen (Section 19, rows 3 and 4).

**Marcus's question** ("the weekend, or since February"). Not answerable for February from anything FinServe holds. It is answerable from the first line of the host's `auth.log`, and possibly further back from the DC-SLO backup appliance (90 days) and from Meridian's own logs, if those exist (Section 20, Evidence Requests ER-01, ER-04, ER-13).

**Decisions needed today** (Section 22): keep `finserve_settle` suspended and do not reinstate the old credential for any reason, including tonight's deadline; restrict the host at the network, image it, and do not rebuild it first; the business decision on tonight's settlement belongs to Finance Operations, the CFO and the CISO, and the SOC's conditions are in Section 22.3; the GRC handoff in Section 27 goes tomorrow morning.

**Detection.** FinServe learned of the Slough activity from Meridian, 33 hours 7 minutes 49 seconds after the first logged host login. No FinServe detection is documented for the host or for `sqldb-uat` (E7 §3; Coverage-Gaps G3 and G7). Detection DET-06 existed in the backlog and could not have fired, because the host's logs are not in Sentinel.

## 13. Evidence Added by Inject 06, Assumptions and Integrity Limits

### 13.1 New sources

| Ref | Source | What it is | Limits |
|---|---|---|---|
| I6-A1 | Email from Operations Risk, Meridian Trust plc, W3 D1 07:12, to `settlement.ops@finserve.example`, cc the CISO | A third-party statement about its own SFTP platform. Eleven authentications against `finserve_settle`, nine successful, from 45.83.220.61, outside the 00:00 to 01:00 window, used to list and retrieve. Account suspended. | No event timestamps, no time zone, no client details. "The weekend" is not defined. Counts are Meridian's. Not verified by FinServe. |
| I6-A2 | DC-SLO SFTP server local syslog extract | Host-local log, "retrieved by hand". Two sessions shown. States that nine further successful authentications "follow the same pattern" and that `auth.log` begins on "W-2 D1". | See 13.3. |
| I6-A3 | Azure Firewall rows in `law-sentinel-prod`, and an empty `SQLSecurityAuditEvents` query | Platform-generated flow records for three connections from 172.20.14.30 to 10.30.2.14 port 1433, rule `CHG-2025-0132-dev-fileshare`, Action Allow. The inject states that 172.20.14.30 is the DC-SLO SFTP server and 10.30.2.14 is `sqldb-uat` in `sub-nonprod`. | Three rows only, no baseline. An Allow is a rule match, not a successful database login. |
| I6-A4 | Message from Marcus Ifill, W3 D1 07:31 | A statement from the Security Operations Manager. | A statement, not a log. Reported facts: SQL audit connector raised twice, storage diagnostics off, SFTP logs local for 30 days with no forwarder. |

Repository documents used in this update: E1 §3.1 (standing firewall exceptions), §6 (telemetry), §8 (DC-SLO decommission); E2 §3 (data services and what the UAT copy contains), §7 (telemetry); E4 §1 (data categories), §4 (the reconciliation path); E6 `03-Business-Processes.md` §4 (P8) and `04-Stakeholders.md`; E7 §1 to §4; E10 §4 (SEC-2025-03). The earlier Inject 04 artefacts are cited here as A1 to A3, as in Sections 2 and 3.

### 13.2 Assumptions added

| # | Assumption or caveat | If it is wrong |
|---|---|---|
| T5 | **Calendar.** W2 D1 is Monday 12 October 2026, W2 D6 is Saturday 17 October, W2 D7 is Sunday 18 October, W3 D1 is Monday 19 October. Derived from this report's own date line (14 October, W2 D3) and the inject's week and day labels. No inject states a calendar date. | Day-of-week labels in Sections 15 and 20 shift together. The relative intervals do not change. |
| T6 | **Host clock.** Syslog lines carry no year or time zone. I treat I6-A2 times as UTC and aligned to the Azure Firewall clock within seconds. Slough was on British Summer Time until Sunday 25 October. | If the host logs local time, its times are one hour later than UTC. The 03:52 reads would be 02:52 UTC and the gap to the 04:11:09 UTC flow would be 1 hour 19 minutes, not 19. The ordering (reads, then connection) survives. The "nineteen minutes" proximity does not. Clock drift would blur it further. This is the single most consequential unverified assumption in the link between the file reads and the SQL connection. Settled by ER-01 and ER-02. |
| T7 | **Two platforms, one account name.** `finserve_settle` exists on Meridian's SFTP platform (the delivery target, E4 §4) and as a login on the DC-SLO host (I6-A2). I treat them as two accounts. I do not know whether they share a password. | If they share a password, one exposure is the other. |
| T8 | **Counts are not merged.** The host extract implies eleven successful host authentications (two shown plus nine described). Meridian reports eleven authentications, nine successful, on its own platform. Different systems, different observers, different success counts. I do not equate them. | See Section 19, row 12. |
| T9 | **"Accepted password" lines** record a successful password authentication for the named account from the logged peer address, as the host saw it. | A proxy or NAT in front of the host could change what the host sees (step P5). |
| T10 | **`open ... flags READ` lines** record a request to open a file for reading. The extract has no matching `close` lines with byte counts, so completion and volume are not shown. | If the full log shows completed reads, "requested" becomes "read". |
| T11 | **Asset mapping.** I take the inject's statement that 172.20.14.30 is the SFTP server and 10.30.2.14 is `sqldb-uat`. I have not checked it against an asset register. | Every statement about the 04:11 flows depends on it. |
| T12 | **Azure Monitor platform metrics** are retained independently of diagnostic settings, for about 93 days. This is general product knowledge, not a FinServe document. | ER-11 falls back to "not available". |

### 13.3 Integrity of the host extract and other limits

- **Provenance.** "Retrieved by hand." Who retrieved it, when, how, and whether the whole file was searched is not recorded. No hash exists. It is a selection: two of eleven sessions, no failed attempts, no `close` lines.
- **Tamper evidence.** The log sits on the host the actor logged in to. There is no evidence of tampering and no evidence of privilege above the SFTP account. A local log on a host the actor touched is still not tamper-evident, so I treat I6-A2 as **reliable enough to act on and not yet reliable enough to rely on**. The Azure Firewall rows are platform-generated and are the better-protected evidence.
- **Time.** Syslog has no zone (T6). Log Analytics `TimeGenerated` is UTC (product behaviour, not a FinServe document). Meridian gives no zone.
- **"No results".** A query against a table that does not exist normally fails with a resolution error. "No results" suggests `SQLSecurityAuditEvents` exists in the workspace and holds nothing for `sqldb-uat` **[A, low confidence: portal behaviour varies]**. That would mean some SQL audit data may be reaching the workspace, which contradicts E7 §1 ("Not connected"). Q17 settles it. Either way, an empty result from a source that does not collect `sqldb-uat` says nothing about what `sqldb-uat` did.
- **Label.** "W-2 D1" is not defined by the calendar in T5. It is Monday 14 or 21 September. Marcus's "two weeks before the first entry" points to about Saturday 3 October. The three readings differ by up to three weeks, and the first line of the file settles it (ER-01).
- **The extract may be incomplete and the nine sessions are invisible.** Anything I say about what the actor did not do is limited to what the extract shows.

## 14. Relationship Assessment: One Incident or Two?

**Verdict.**

| Question | Assessment | Confidence |
|---|---|---|
| Should this be handled as one incident record? | Yes. Merge. | **High** |
| Is the Slough activity by the same operator as the M365 activity? | Probably | **Moderate to high** **[A]** |
| Did the M365 downloads supply the Slough credential? | Possible and unproven | **[H]**, no confidence rating until ER-14 is answered |

### 14.1 The case for linking

| # | Evidence | Class | Weight | Independent of the address? |
|---|---|---|---|---|
| L1 | The same address, 45.83.220.61, signs in to M365 as `r.oduya` (A2, W2 D1 07:59:44 to 08:14:55), logs in to the host (I6-A2) and is named by Meridian (I6-A1). | **[F]** that the string is identical in three artefacts | High as an anchor. Limited by "an address is not an actor" (14.3). AS205544 is a hosting network (A2), so an address may be shared or re-let. Five days separate the two uses. | Not applicable: this is the address |
| L2 | Same business target. The M365 session read the Settlement Ops mailbox and took `Settlement runbook v4.docx` and `DR-SLO access notes.txt`. The host sessions read settlement archive files and the FinRecon delivery configuration. Meridian reports use of the settlement account. | **[F]** for each event, **[A]** that they cohere | Moderate to high | Yes |
| L3 | **Foreknowledge of a path.** Session 2 opens `/opt/finrecon/conf` 18 seconds after login with no directory traversal shown. That path is not obvious from "settlement". | **[A]** | Moderate, and conditional on the extract being complete | Yes |
| L4 | **Order and lag.** Collection (W2 D1, 08:23:02 last event), then use (W2 D6, 22:04:11), 5 days 13 hours 41 minutes later, then Meridian. This is the order an operator who needed the documents first would follow. | **[A]** | Low to moderate. Almost any story has this order. | Yes |
| L5 | **Vocabulary.** The 12 October inbox rule keywords (meridian, settlement, reconciliation) name the process, and the counterparty, that the host sessions then targeted. | **[F]** keywords, **[A]** inference | Low to moderate | Yes |
| L6 | **Behaviour.** Both host sessions list directories within 8 to 18 seconds of login. Consecutive file-open requests are spaced 38 or 39 seconds apart in both sessions, 5 hours 32 minutes apart (22:06:52 to 22:07:31, 03:52:02 to 03:52:40, 03:52:40 to 03:53:18). Consistent with one operator or one tool. | **[A]** | Low. Equally what a scripted client by anyone would do. | Yes |
| L7 | Meridian describes list-and-retrieve on an account whose use is write-only. That is the same kind of behaviour as on the host (enumerate, then read). | **[A]** | Low to moderate | Yes |

### 14.2 Alternatives I considered

| # | Alternative | Why I do not prefer it | What would separate it from the link |
|---|---|---|---|
| N1 | **A different actor behind the same address** (shared hosting, rented proxy, VPN exit). | It needs two independent parties on one address within five days, both aimed at the same narrow process, the second holding a working Slough credential. It cannot be excluded, because the address is in a hosting network. | Client signatures (SSH banner and key-exchange details in the host's verbose logs and in Meridian's logs). Address history from external intelligence, which this exercise does not provide. |
| N2 | **Authorised use** by a FinServe user, Corebridge, Solvex or another supplier. | Meridian does not hold the address on its allowlist. The sessions read files the delivery integration does not need (Meridian: "retrieval is not something your integration does"). The address geolocates to a UK hosting network (A2). Nobody has yet said it is theirs. | A yes or no from the named owners (ER-16). |
| N3 | **Two intrusions that feed each other** (credential obtained earlier by someone else, then used by the M365 operator, or the reverse). | The response is identical: one record, one credential question. Attribution is not needed to act. | Host and Meridian history before W2 D1 (ER-01, ER-04, ER-13). |
| N4 | **A person with prior Slough knowledge** (staff or supplier). | No positive indication. Foreknowledge of the path (L3) fits this as well as it fits documents. I cannot exclude it and will not speculate about individuals. | Source of the credential (ER-14, ER-13). |

### 14.3 What the link does not establish

- **An address is not an actor.** The link rests on an address in a hosting network. It supports "the same infrastructure", and the rest of the table supports "probably the same operator".
- **An authenticated session is not token replay.** A2 shows an M365 session from the address carrying an MFA claim. Token replay after an adversary-in-the-middle capture remains my working explanation **[A]**. A real-time relay of password and MFA, an approved prompt, and token theft from a device would look the same in A2. Nothing in the link depends on which.
- **The link does not tell us the mechanism.** It does not tell us whether the downloads supplied the credential (Section 16, P4).

### 14.4 Why merge, and what would make me split

I merge because the response is shared: one exposed credential family, one set of owners, one evidence timeline, and a five-day gap between the halves that nobody should be able to treat as someone else's incident. A split is cheap later. A missed link is not.

I would reopen the question if any of these happen: a named owner says the address is theirs (N2); the host's client signature differs from Meridian's (N1); external intelligence shows the address as a long-lived multi-tenant proxy exit.

## 15. Revised Timeline

Monday 12 October to Monday 19 October, all times UTC (T1, T6). Confidence uses three words: **Proven** (an artefact or a source document shows it), **Assessed** (my reasoning from the facts) and **Unknown** (cannot be determined from what we hold). Sources: A1 to A3 are the Inject 04 artefacts, I6-A1 to I6-A4 the Inject 06 artefacts. I have not invented a timestamp for any event that is not documented. Monday 12 October rows are condensed. Section 3 has the full reasoning for them.

| Timestamp (UTC) | Event | Evidence/source | Confidence (Proven / Assessed / Unknown) | Analyst interpretation |
|---|---|---|---|---|
| **Mon 12 Oct** | | | | |
| 07:41:02 | `r.oduya` signs in to Exchange Online from the corporate network. | A2 | **Proven** (the sign-in). **Assessed** that it is Rachel (T2). | The baseline: a normal sign-in 11 minutes before the lure. |
| 07:52:09 to 07:52:11 | Spoofed "Nadia Ferreira" email sent from 203.0.113.87 and delivered to six Finance Operations recipients. SPF fail, DKIM none, DMARC fail. | A1 | **Proven** | The lookalike Reply-To and the failed checks show Nadia did not send it. Six recipients means up to five more possible victims (Section 5.3, row 5). |
| 07:52 to 07:58 | Credentials and MFA are captured on a lookalike page. | none direct | **Assessed** (Section 3) | Inferred from Rachel's "done" and from an MFA claim that appears 1 m 44 s later. No artefact shows the page visit. |
| 07:58 | Rachel replies "done". | A1 (ticket) | **Proven** | The last user action before the first attacker session. |
| 07:59:44 | First session from 45.83.220.61, Exchange Online, MFA claim in the token. | A2 | **Proven** (session and claim). Token replay **Assessed**. | A session that carries an MFA claim and never saw a prompt points to relay or replay. This is the earliest attacker activity in any artefact. |
| 08:02:17 to 08:02:44 | Graph sign-in, then `New-InboxRule` named "." hiding meridian, settlement and reconciliation mail. | A2, A3 | **Proven** | A concealment rule within three minutes: a person at the keyboard, aiming at the settlement process. |
| 08:05:19, 08:09:03 | Inbox and "Settlement Ops (shared)" read via Graph. | A3 | **Proven** (access). Item counts **Unknown**. | Reading settlement correspondence. The volume is not in the extract. |
| 08:14:55 to 08:16:30 | `Settlement runbook v4.docx` accessed, then downloaded. | A3 | **Proven**. Contents **Unknown**. | A process document: it tells its holder how settlement works. |
| 08:22:41 to 08:23:02 | `DR-SLO access notes.txt` accessed, then downloaded. **Last attacker event in the M365 extract.** | A3 | **Proven**. Contents **Unknown**. | The name suggests Slough access details. I do not infer contents from a name. This starts the clock on the Slough credential question (P4). |
| 08:31, 08:47 | Phishing report; Sentinel incident 2026-W2D1-0093 ("Atypical travel", Medium). | A1, A2 | **Proven** | Detection came 47 minutes after the first attacker session, from a location rule that did not see what the session did. |
| 09:31:08 | `r.oduya` signs in from the corporate network. | A2 | **Proven**. Rachel **Assessed**. | Says nothing about whether the attacker session was revoked. |
| **Tue 13 to Fri 16 Oct** | | | | |
| all four days | **No artefact held.** A gap in what has been supplied, not evidence that nothing happened. M365 sign-in and audit data (60 days), Azure Firewall and Fortigate (60 days) and the host's `auth.log` all still exist for these days and have not been supplied. | none | **Unknown** (Section 19, rows 5 and 13) | The stretch in which the actor held the downloaded files and FinServe held a live incident. ER-01, ER-05 and ER-15 would fill it. |
| Wed 14 Oct | Inject 04 report issued. First-hour actions include "copy the DC-SLO SFTP server's local logs" and a CISO decision on rotating the static SFTP credential. | this report, v1 | **Proven** that it was issued. Actions **Unknown** (ER-16). | If the logs were not copied and the credential not rotated, the exposure ran on from here. |
| **Sat 17 Oct** | | | | |
| 22:04:11 | **First logged host login.** `Accepted password for finserve_settle from 45.83.220.61 port 51122` on `sftp-slo`. 5 d 14 h 04 m 27 s after the first M365 sign-in. | I6-A2 | **Proven** (T6, T9) | The first evidence of use of Slough access. Whether it is the first ever is **Unknown** (Section 20). |
| 22:04:19, 22:04:20 | `opendir` on `/settlement/outbound` and `/settlement/archive`. | I6-A2 | **Proven** | Directory listing 8 and 9 seconds after login: orientation, not a delivery job (L6). |
| 22:06:52, 22:07:31 | `open ... flags READ` on `/settlement/archive/SETL-2026W2D5.csv` and `SETL-2026W2D4.csv`. | I6-A2 | **Proven** that reads were requested. Completion and contents **Unknown** (T10). | Interest in settlement data. The 39-second spacing is consistent with one tool or one operator (L6). |
| 22:19:07 | Disconnect. Session length 14 m 56 s. | I6-A2 | **Proven** | End of session 1. |
| 23:30 | Documented nightly extract from Corebridge to the host (E4 §4). | E4 | Documented. Occurrence **Unknown**. | Whether this extract and the 00:15 delivery completed normally on this night and the next is not stated anywhere. |
| **Sun 18 Oct** | | | | |
| 03:51:44 | `Accepted password for finserve_settle from 45.83.220.61 port 44518`. 5 h 32 m 37 s after session 1 closed. | I6-A2 | **Proven** | A second login by the same account from the same address. |
| 03:52:02 | `opendir "/opt/finrecon/conf"`, 18 seconds after login, no traversal shown. | I6-A2 | **Proven** | Goes straight to the application's configuration directory. Foreknowledge of the path is **Assessed** (L3). |
| 03:52:40 | `open "/opt/finrecon/conf/deliver.cfg" flags READ`. | I6-A2, E4 | **Proven** (request). That today's file matches the documented one **Assessed**. | E4 §4 documents `deliver.cfg` as holding the Meridian host, user and static password. This is a request for a credential file. |
| 03:53:18 | `open "/opt/finrecon/conf/refresh_uat.ps1" flags READ`. | I6-A2 | **Proven** (request). Purpose and contents **Unknown**. | No document describes this script. The name is a reason to ask what it is, not a basis for saying what it holds. |
| 04:02:55 | Disconnect. Session length 11 m 11 s. No file-operation lines for the last 9 m 37 s. | I6-A2 | **Proven**. What happened in that time **Unknown**. | Idle, an unlogged action, or lines missing from the extract. |
| 04:11:09 | Allow, 172.20.14.30 to 10.30.2.14:1433, rule `CHG-2025-0132-dev-fileshare`. 8 m 14 s after disconnect, 17 m 51 s after the last file request, 19 m 07 s after the first `opendir` (T6). | I6-A3 | **Proven** | The network permitted a connection from the host to the UAT database. It was not made inside the 03:51:44 session. Nothing about login or content follows (Section 17). |
| 04:11:12 | Second Allow, same tuple. | I6-A3 | **Proven** | Three seconds after the first. Consistent with one client opening two connections. |
| 04:14:38 | Third Allow, same tuple. 3 m 29 s after the first. | I6-A3 | **Proven** | A third connection. Duration, success and content are not shown. |
| after 04:14:38 | Nothing shown. | none | **Unknown** | The log records connection starts, not ends. Whether the connection succeeded, what it ran, what came back and whether it continued is not known. |
| **Between Sat 17 and Mon 19 Oct** | | | | |
| time unknown | Nine further successful host authentications "follow the same pattern". | I6-A2 (described) | **Proven** that they are described. Content **Unknown**. | With the two shown, eleven host logins. Kept apart from Meridian's eleven (T8). Their times and operations are the biggest hole in this table. |
| time unknown | Meridian's platform logs eleven authentications, nine successful, list and retrieve, "over the weekend". | I6-A1 | Third-party statement. Times **Unknown**. | The same address on a second platform, doing what it did on the host (L7). |
| time unknown, before 07:12 | Meridian suspends `finserve_settle`. | I6-A1 | Third-party statement | Stops use of that credential on Meridian's side only. |
| **Mon 19 Oct** | | | | |
| 07:12 | Meridian emails settlement.ops and the CISO. 33 h 07 m 49 s after the first logged host login, 27 h 00 m 51 s after the 04:11:09 flow. | I6-A1 | **Proven** | FinServe learned of the Slough activity from a third party. |
| 07:31 | Marcus replies, 19 minutes after Meridian's email. | I6-A4 | **Proven** | Confirms the gaps: SQL audit connector raised twice, storage diagnostics off, host logs local only. |
| tonight 23:30 and 00:15 | Tonight's extract and delivery. Meridian: "Tonight's settlement will not deliver." | I6-A1 | Statement of intent. Outcome **Unknown**. | A live business impact (Section 22.3). |

**Where the timeline is thin**

- **The four days between the two halves.** Nothing is held for 5 days 13 hours 41 minutes after 08:23:02 on Monday 12 October. This is the stretch in which the actor had the downloaded files and FinServe had a live incident.
- **The nine unseen host sessions and Meridian's eleven events.** Their times, sources and operations are the main material the timeline lacks.
- **Containment between Inject 04 and Inject 06.** If Rachel's sessions were revoked on Monday 12 or Wednesday 14 October, the M365 side stopped there. If they were not, the M365 session may have been live all week. Q2 shows the last sign-in from the address.

> **Update (Inject 07):** the timeline above is not changed. The row at 03:53:18 recorded `refresh_uat.ps1` as "purpose and contents **Unknown**". The platform team has since supplied an extract of the script (I7-A2). It holds a plain-text service-account credential shared by the production and UAT connections. Section 32.2 sets the 18 October sequence against it.

## 16. Attack Path Reconstruction: Stolen Session Token to Authenticated Session in Slough

I use the inject's phrase "stolen session token" as a working description of the M365 stage. The artefacts show an authenticated session with an MFA claim. They do not show how that claim was obtained (Section 14.3).

### 16.1 Steps, evidence and confidence

| Step | Claim | Artefact and time (UTC) | Proof or inference | Confidence |
|---|---|---|---|---|
| **P0** | A spoofed email with a lookalike Reply-To reaches Rachel. | A1, W2 D1 07:52:11 | **Proof** (header artefact; delivery to six recipients per the service desk ticket) | High |
| **P1** | Rachel follows the link and completes sign-in and MFA on a page the actor controls. | none direct. Her reply at 07:58 (A1 ticket) and the replayed MFA claim at 07:59:44 (A2). | **Inference** | Moderate to high |
| **P2** | An authenticated M365 session starts from 45.83.220.61 and carries an MFA claim. | A2, W2 D1 07:59:44 | **Proof** of the session and the claim. Token replay is **inference.** | Session: high. Mechanism: moderate. |
| **P3** | In that session the actor hides related mail, reads the inbox and the shared settlement mailbox, and downloads the runbook and the Slough access notes. | A3, 08:02:44 to 08:23:02 | **Proof** that the events were logged. Contents and intent are **inference.** | High that it happened. Contents **[U]**. |
| **P4** | The actor learns the host's address, an account name and a working credential for it. | **No artefact.** Somewhere between 08:16:30 on W2 D1 and 22:04:11 on W2 D6 at the earliest. | **Unsupported** (**first unsupported transition**) | Not rated. Candidate explanations H1 to H5 in 16.2. |
| **P5** | The host is reachable from 45.83.220.61. | I6-A2: sshd logs the peer as 45.83.220.61. No other artefact. | **Inference** from the logged peer address (T9) | Moderate to high |
| **P6** | The actor authenticates by password as `finserve_settle`. Session 1. | I6-A2, W2 D6 22:04:11 | **Proof** of the log line (integrity limits in 13.3). Attribution to the actor is **inference** (14.1). | High that the line exists. Moderate to high that it is the actor. |
| **P7** | The actor lists the settlement directories and requests two archive files. | I6-A2, 22:04:19 to 22:07:31 | **Proof** of the requests. Transfer and contents **[U]**. | High (requests). Low (what was taken). |
| **P8** | In session 2 the actor goes straight to `/opt/finrecon/conf` and requests `deliver.cfg` and `refresh_uat.ps1`. | I6-A2, 03:51:44 to 03:53:18 | **Proof** of the requests. Foreknowledge of the path is **inference** (L3). | Requests: high. Foreknowledge: moderate. |
| **P9** | The actor authenticates to Meridian's platform as `finserve_settle`, lists and retrieves. | I6-A1, times unknown | **Third-party statement** | Moderate (not first-hand) |
| **P10** | A connection from the host to `sqldb-uat` is permitted at 04:11 to 04:14. | I6-A3 | **Proof** of the permitted flows. Initiator, login, queries and data **[U]**. | High (flows). None (effect). |

**Alternatives and the next confirming artefact, by step**

| Step | Alternative explanations | Next confirming artefact |
|---|---|---|
| P0 | None material. | Message trace (Q3), and the original email forwarded as an attachment. |
| P1 | Malware on Rachel's device took the token (infostealer). Device-code or consent phishing. Her "done" referred to something else. | The interactive sign-in row in Q1, click telemetry (Q4), Rachel's own account, device telemetry (ER-18). |
| P2 | A live relay of password and MFA. An approved MFA prompt. Token theft by malware. | Q1: `UserAgent`, `SessionId` and continuity between interactive and non-interactive rows. ER-18. |
| P3 | None for the logged events. For intent: reconnaissance, fraud or access brokering. | Q8 (full `AuditData`). ER-14 for what the files hold. |
| P4 | H1 to H5 (16.2). | ER-14 (contents and history), ER-13 (Meridian's first use), ER-01 (failed attempts). |
| P5 | A proxy or NAT in front of the host changes the apparent source. A different route. The line records another hop. | ER-06 and ER-07 (Fortigate), ER-02 (sockets and `sshd` settings). |
| P6 | Authorised use from the same address by a known party (N2). | ER-16 (yes or no), ER-01 (baseline of normal logins). |
| P7 | Requests that failed. Automated scanning. | ER-01 (`close` lines and byte counts), ER-03 (image). |
| P8 | The path was learned from a listing in an unseen session or earlier in the session. A scripted client. | ER-01 (every session's operations), ER-14. |
| P9 | Meridian's count or classification differs from the facts. | ER-13. |
| P10 | X1 to X4 (17.4). | ER-05, ER-09, ER-11, ER-02, ER-03. |

### 16.2 First unsupported transition, and the ways the middle could be joined

**P3 to P6 is where evidence ends.** On one side the M365 session downloaded two files. On the other, five days later, a password login to a host that FinServe documents do not describe as reachable from the internet. No artefact joins them. P4 (how the actor acquired the credential) and P5 (how the actor reached the host) are both unevidenced, and P4 is the earlier of the two.

| # | Hypothesis for P4 | Class | Test | What a "yes" tells us |
|---|---|---|---|---|
| H1 | The credential or the address was in `DR-SLO access notes.txt` or `Settlement runbook v4.docx`. | **[H]** Plausible. The names describe a Slough access note and a settlement runbook, but I have not inferred their contents from the names. | ER-14: a named reviewer states what each file holds and when each item was added (version history). | The 12 October download is the likely source, and the compromise window is narrow. |
| H2 | It was elsewhere in M365 that the session read: Rachel's mailbox, the Settlement Ops shared mailbox, other SharePoint pages. | **[H]** | ER-15 and Q15: all activity from the address, including pages viewed without a download. | The same, with a wider set of documents to rotate. |
| H3 | The actor held it before W2 D1 (earlier compromise, or a copy that has circulated). The Meridian delivery credential has been static since the arrangement began, and a plaintext copy sits in the architecture documentation (E4 §4; Coverage-Gaps G3). | **[H]** Cannot be excluded | Host and Meridian history before 12 October (ER-01, ER-04, ER-13). Who has had access to the documents containing the value. | Earliest compromise moves back (Section 20). |
| H4 | The actor guessed or sprayed it. | **[H]** Low | Failed attempts and `Invalid user` lines in the full `auth.log` (ER-01). Meridian's two unsuccessful events (I6-A1) fit a mistyped credential as well as a guess. | A burst of failures before the first success would be strong. Their absence points to a known credential. |
| H5 | A person with prior knowledge (staff or supplier) used it. | **[H]** No positive indication | No log test. | Cannot be settled from logs. |

**Why the Meridian first-use time matters.** The only artefact that shows the actor reading `deliver.cfg` is at 03:52:40 on W2 D7. If Meridian's log shows a successful `finserve_settle` login from the address **before** that time, the actor already held the Meridian credential and the host read was confirmation, not acquisition. This turns on one timestamp from a third party (ER-13).

### 16.3 What was observed, what is inferred, and what is confirmed taken

| Object | Observed access | Inferred intent | Exfiltration status |
|---|---|---|---|
| `Settlement runbook v4.docx`, `DR-SLO access notes.txt` (SharePoint) | `FileAccessed` and `FileDownloaded` by the session (A3) **[F]** | Mapping the settlement process and the Slough estate **[A]** | The download events record a transfer to the session holder **[F]**. That the holder is the actor rests on P2 **[A]**. Contents unknown. |
| Rachel's inbox, Settlement Ops shared mailbox | `MailItemsAccessed` via Graph (A3) **[F]** | Reading settlement correspondence **[A]** | Not established. Item counts unknown. |
| `/settlement/archive/SETL-2026W2D5.csv`, `SETL-2026W2D4.csv` | Open-for-read requests logged **[F]** | Collecting settlement data **[A]** | **Not confirmed.** No `close` or byte-count lines shown. The contents are not known and I do not infer them from the names. |
| `deliver.cfg`, `refresh_uat.ps1` | Open-for-read requests logged **[F]** | Obtaining the delivery credential **[A]** (`deliver.cfg` is documented as holding it, E4 §4). `refresh_uat.ps1`: **[U]**. | **Not confirmed.** |
| Meridian's platform | List and retrieve, per Meridian | Collecting what Meridian holds **[A]** | Retrieval reported by Meridian. What was retrieved is **[U]**. |
| `sqldb-uat` | A permitted network flow **[F]** | **[U]** | **None established.** No login, query or data is evidenced. |

> **Update (Inject 07):** in the last row of the table in 16.3, `refresh_uat.ps1` is no longer **[U]**. See Section 32.1 (I7-N6) and Section 32.3.

### 16.4 How the six elements relate

The path above is built from six elements. This table says what each one is, how it connects to the next, and where the connection is evidence and where it is inference.

| Element | What the artefacts show | Connection to the next | Evidence or inference |
|---|---|---|---|
| **Stolen session token** | A session from 45.83.220.61 carrying an MFA claim, one minute 44 seconds after Rachel's "done" (A2). Token replay is my working explanation. | Gave the actor Rachel's mailbox and SharePoint, from which two files were taken (A3). | Session: **proof**. Token mechanism: **inference** (14.3). |
| **Authentication activity** | Password logins by `finserve_settle` from the same address on two platforms: eleven successful on the host (two shown, nine described) and eleven on Meridian's, nine successful (I6-A1, I6-A2; T8). | Same address, a different system, five days later. | Address match: **proof**. Same operator: **inference**, moderate to high (Section 14). |
| **SFTP account access** | Two host sessions listing directories and requesting four files (I6-A2). | The second session went to the configuration directory. | Requests: **proof**. Foreknowledge: **inference** (L3). |
| **Reading of configuration files** | Open-for-read requests for `deliver.cfg` and `refresh_uat.ps1` (I6-A2). | One file is documented to hold a credential. | Requests: **proof**. That the content was delivered: not shown (T10). |
| **Potential credential exposure** | `deliver.cfg` is documented as holding the Meridian credential, static since 2019 (E4 §4). The contents of `refresh_uat.ps1` are unknown. | If obtained, the Meridian credential works on Meridian's platform, and Meridian reports use. | Exposure: **assessed**. Logins to the host-local account: **proof of login**. How that credential was obtained: **unproven** (P4). I do not claim that any credential was taken from these files. |
| **Connections from SFTP to `sqldb-uat`** | Three Allow flows at 04:11 to 04:14 (I6-A3). | None shown. | Flows: **proof**. Any link to the file reads: **unproven** (Section 17). |

## 17. Database Access Assessment

This section assesses the three Azure Firewall records of connections from `sftp-slo` (172.20.14.30) to `sqldb-uat` (10.30.2.14) on port 1433 (I6-A3). The mapping of the two addresses to those assets is taken from the inject (T11). `sqldb-uat` matters because it is a nightly copy of production in which names and email addresses are masked, and account numbers, balances, transaction history and National Insurance numbers are copied unmasked (E2 §3).

### 17.1 The three records

| # | Time (UTC) | Source to destination | Action | Rule | Timing |
|---|---|---|---|---|---|
| 1 | Sun 18 Oct 04:11:09 | 172.20.14.30 to 10.30.2.14:1433 | Allow | `CHG-2025-0132-dev-fileshare` | 8 m 14 s after the SFTP session closed. 17 m 51 s after the `refresh_uat.ps1` request (T6). |
| 2 | 04:11:12 | same | Allow | same | 3 seconds after record 1 |
| 3 | 04:14:38 | same | Allow | same | 3 m 29 s after record 1 |

### 17.2 What the firewall records prove, and what they do not

| They prove | They do not prove |
|---|---|
| A flow from the host's address to the database's address on 1433 matched an Allow rule, three times, at those times. | That the connection completed. |
| A route from `sftp-slo` to `sqldb-uat` exists and is open. | That a login was attempted, which account was used, or whether it succeeded. |
| The rule that allowed it is labelled for a different purpose: E1 §3.1 documents `CHG-2025-0132` as Dev subnet to a shared-services file server, not DC-SLO to UAT SQL **[A]** that the rule is broader than documented. | That any statement ran, or that any row or byte came back. |
| The rows are generated by the platform, outside the host. They are better protected than the host log (13.3). | Who or what started the connection: a person, a job or a tunnel. |
| | That it was hostile, or that it was routine. |
| | That these are the only connections. There are three rows, no baseline, and the query window is not stated. |

A network-rule row records that a flow matched a rule. It does not record login, statements, bytes or duration. This is general product behaviour, not a FinServe document.

### 17.3 Why the absence of SQL audit events is not evidence that no database activity occurred

Evidence is informative only if, had the event happened, the source would have shown it. Ask that of the empty query. Had someone read every row of `sqldb-uat` on 18 October, would `SQLSecurityAuditEvents` in `law-sentinel-prod` have held a record? Only if the database writes audit events to that workspace. E7 §1 says the Azure SQL auditing connector is **Not connected**. E7 §3 records auditing as on only for the managed instance, writing to storage. Nothing records auditing on `sqldb-uat` at all (Coverage-Gaps G7 and Q7). So the empty result would have looked the same whether the database was read or not. **It has no value in either direction.**

There are four reasons the result could be empty. They have different fixes, and the configuration (ER-09) says which applies:

1. Auditing is enabled and writes to a destination Sentinel does not read (storage, or another workspace). Records exist. **Not forwarded.** Recoverable.
2. Auditing was never enabled on `sqldb-uat`. No record was ever created. **Not enabled.** Not recoverable.
3. Auditing wrote records and retention removed them. **Aged out.**
4. The workspace table is absent, or ingestion failed (13.3). **Not forwarded.**

Marcus's statement points the same way: "I can tell you a connection happened because the firewall saw it. I cannot tell you what it did, what it ran, or what came back" (I6-A4).

### 17.4 What the 04:11 connection could be

Three facts constrain the explanations. It began 8 minutes 14 seconds **after** the SFTP session closed, so it was not made inside that session. The `sftp-server` lines show only SFTP operations. E4 documents the nightly UAT refresh (F10, 02:00) as running "within Azure", yet a script named for it sits on this host.

| # | Explanation | For | Against | What separates it |
|---|---|---|---|---|
| X1 | Started by the actor on the host, by a shell, a second session, or a planted job. | Timing after the reads. A host with no documented reason to reach UAT SQL. | No evidence of code execution. SFTP alone does not run a database client. | Whether `finserve_settle` has a shell (ER-02), other sessions between 04:02 and 04:15 (ER-01), cron and timers (ER-02), the host image (ER-03). |
| X2 | A scheduled or routine job on the host (for example, the UAT refresh run from this host). | A script named for the refresh sits on this host. Three connections in 3.5 minutes look like a short script. | E4 says the refresh runs at 02:00 within Azure. 04:11 is not 02:00. | Baseline: does 172.20.14.30 connect to 10.30.2.14 on earlier nights, and when (Q12, ER-05)? |
| X3 | A persistence job the actor planted earlier. | Fits X1 and X2 timing. | No write operations are shown in the extract. | Write operations in the full sftp log, timer and cron definitions, file times (ER-01, ER-02). |
| X4 | A different party using the host. | None. | None. | Full `auth.log` for other sessions (ER-01). |

I do not rank X1 to X4. The evidence supports "a connection was permitted" and nothing about who made it or what it did. Q12 and Q13 use data FinServe already holds and may settle X2 in one query.

> **Update (Inject 07):** explanation X2 is revised, and X5 and X6 are added. The script copies first and then masks over a second connection, so connections to UAT follow the end of the copy and not the 02:00 start. Section 32.2 has the revised table. X1 to X6 remain unranked.

### 17.5 Can data access or exfiltration be confirmed?

| Question | Answer | Why |
|---|---|---|
| Can database access be confirmed? | **No.** | The only evidence is a network permit. No login, session or statement is evidenced in anything we hold. |
| Can specific operations be identified? | **No.** | No source of statements exists in Sentinel for `sqldb-uat`. Whether one exists elsewhere is unknown (17.3). |
| Can data extraction be confirmed? | **No.** | Nothing shows rows returned or bytes moved. |
| Can exfiltration be confirmed? | **No.** | Nothing shows data leaving the estate. |
| Can exfiltration be excluded? | **No.** | Routes exist that we cannot see: unseen host sessions, a tunnel through the host, a storage export (storage diagnostics are off), traffic to the internet (Fortigate traffic logs are not shown to reach Sentinel). Section 19, rows 1 to 4. |

**What would change the answers:** `sqldb-uat` auditing configuration and any audit records (ER-09), platform metrics and Query Store (ER-11), a point-in-time restore (ER-12, hard limit Sunday 25 October 04:11), the baseline of host-to-database flows (ER-05), and the full host log for a session open at 04:11 (ER-01).

### 17.6 Why this matters

`sqldb-uat` is a nightly copy of production. Names and email addresses are masked. Account numbers, balances, transaction history and National Insurance numbers are copied unmasked (E2 §3). If the connection read data, the data is restricted customer data (E4 §1, D2 and D3).

## 18. Evidence Assessment

Three levels, as the brief asks. Proven means a log, a configuration record or a project document shows it. Assessed as Likely means I am reasoning from more than one piece of evidence. Cannot Rule Out means no evidence we hold can confirm or exclude it. IDs are used in later sections.

### 18.1 Proven

| ID | Statement | Source | Limit |
|---|---|---|---|
| I6-P1 | On Monday 12 October a spoofed email was delivered to six Finance Operations recipients, with SPF fail, DKIM none and DMARC fail. | A1 | Header artefact and service desk notes |
| I6-P2 | A session from 45.83.220.61 started at 07:59:44 carrying an MFA claim. | A2 | Token replay is an assessment, not shown |
| I6-P3 | That session created the inbox rule ".", read the inbox and the shared settlement mailbox, and downloaded `Settlement runbook v4.docx` and `DR-SLO access notes.txt` (08:02:44 to 08:23:02). | A3 | Contents of the files, and anything after 08:23:02, unknown |
| I6-P4 | `finserve_settle` logged in to `sftp-slo` by password from 45.83.220.61 at Sat 17 Oct 22:04:11 and Sun 18 Oct 03:51:44. | I6-A2 | Two sessions of eleven. Hand-retrieved extract, no hash, time zone assumed (13.3, T6). |
| I6-P5 | Those sessions requested to open two settlement archive files, `deliver.cfg` and `refresh_uat.ps1` for reading. | I6-A2 | Requests only. No `close` lines or byte counts (T10). |
| I6-P6 | Three Allow records from 172.20.14.30 to 10.30.2.14:1433 at 04:11:09, 04:11:12 and 04:14:38. | I6-A3 | A rule match, not a login (Section 17) |
| I6-P7 | The SQL audit query for `sqldb-uat` returned no rows in `law-sentinel-prod`, and the Azure SQL audit connector is not connected. | I6-A3; E7 §1 | Says nothing about audit data elsewhere |
| I6-P8 | The SFTP host logs locally for 30 days with no forwarder and is not onboarded to Sentinel. Storage diagnostics are off. | E7 §1, §3; I6-A2, I6-A4 | Documents and a statement |
| I6-P9 | Meridian states that it logged eleven authentications on `finserve_settle`, nine successful, from the same address, outside the delivery window, used to list and retrieve, and that it suspended the account. | I6-A1 | A third-party statement. FinServe holds no Meridian log. |
| I6-P10 | `deliver.cfg` is documented as holding the Meridian host, user and a static password unchanged since 2019. | E4 §4 | Document |
| I6-P11 | `sqldb-uat` is documented as a nightly copy of production with names and email masked and account numbers, balances, transaction history and National Insurance numbers unmasked. | E2 §3 | Document. Not verified by a query. |
| I6-P12 | The Allow rule that matched the 04:11 flows is documented for a different purpose (Dev subnet to a file server). | I6-A3; E1 §3.1 | Document against a rule label |

### 18.2 Assessed as Likely

| ID | Statement | Reasoning | Confidence |
|---|---|---|---|
| I6-L1 | The same operator was behind the M365 and the Slough activity. | Same address in three artefacts, same business target, the order of events, the vocabulary and the behaviour (14.1). Alternatives in 14.2. | Moderate to high |
| I6-L2 | The host and Meridian sessions are unauthorised. | Meridian does not hold the address on its allowlist; the sessions read files the delivery integration does not need; nobody has yet claimed the address (ER-16). | Moderate to high |
| I6-L3 | The Meridian delivery credential should be treated as exposed. | `deliver.cfg` is documented as holding it (I6-P10) and the actor asked to open it (I6-P5). | Moderate. It is an assumption for response, not a finding that it was taken. |
| I6-L4 | The actor's aims are wider than settlement-process reconnaissance: credential and data collection as well. | Host reads of the settlement archive and configuration directory, and a connection to a database copy of production (Section 5.2, revised). | Moderate. I cannot rank the aims. |
| I6-L5 | The host accepts SSH from the internet. | sshd logged the peer as 45.83.220.61 (T9). No other artefact. | Moderate to high |
| I6-L6 | The Allow rule is broader than its documented purpose. | It matched DC-SLO traffic to UAT SQL, and E1 §3.1 describes a Dev to file-server rule (I6-P12). | Moderate |
| I6-L7 | The nine unseen host sessions follow the pattern of the two shown. | I6-A2 says so. I cannot verify it. | Low to moderate |
| I6-L8 | FinServe had no detection on the host or the database, and learned of the activity from a third party after 33 hours. | E7 §3; Coverage-Gaps G3, G7; I6-A1 timing. | High |

### 18.3 Cannot Rule Out

| ID | What cannot be ruled out | Why | Gap class (Section 19) | What would settle it |
|---|---|---|---|---|
| I6-C1 | That the connection to `sqldb-uat` was a login that read data. | A flow is not a login, and no source of statements exists in Sentinel (Section 17). | Not forwarded, or Not enabled, or Not supplied | ER-09, ER-11, ER-12 |
| I6-C2 | That someone on the host, or tunnelling through it, started the connection. | The sftp log shows only SFTP operations. No process, shell or socket history is documented. | Not enabled, or Not supplied | ER-01, ER-02, ER-03 |
| I6-C3 | That data left through a storage account or export. | Storage diagnostics are off. | **Never existed** | ER-17 gives volume only |
| I6-C4 | That data left the estate toward the internet. | Fortigate traffic logs are not shown to reach Sentinel. | Not forwarded, or Aged out | ER-06, ER-07 |
| I6-C5 | That the actor was on the host before Sat 17 Oct 22:04:11. | Only an extract was supplied, and the log's oldest lines have rotated out. | Not supplied, then Aged out | ER-01, ER-04 |
| I6-C6 | That anything happened "since February". | Nothing FinServe holds reaches that far. | Aged out. Third party for Meridian. | ER-13, ER-04 |
| I6-C7 | How the actor obtained a working credential (P4). | No log records knowledge passing, and the contents of the two SharePoint files are unseen. | Not supplied. Third party. | ER-14, ER-13, ER-01 |
| I6-C8 | How 45.83.220.61 reached the host (P5). | No Fortigate policy, NAT or traffic data supplied. | Not supplied | ER-06, ER-07 |
| I6-C9 | What the six files contain, including `refresh_uat.ps1`. | Not supplied. I do not infer contents from names. | Not supplied | ER-14, ER-02, ER-03, ER-10 |
| I6-C10 | What the nine unseen sessions did, including writes, renames and deletes. | Described, not shown. | Not supplied | ER-01 |
| I6-C11 | That settlement files or deliveries were altered. | No file integrity monitoring documented. The extract shows read requests only. | Not enabled. Third party. | ER-01, ER-13, C-11 |
| I6-C12 | That the M365 session continued after 08:23:02. | Only the Inject 04 extract was supplied. | Not supplied | ER-15, ER-19 |
| I6-C13 | That other DC-SLO workloads share the account or credential. | The 11 workloads are not identified. | Not supplied | C-16 |

**Has "Cannot Rule Out" grown since Inject 04?** Yes. Section 5.3 listed eight items, all about the M365 side. Inject 06 adds the host, the database, the exfiltration routes, the credential path and the time before 17 October (I6-C1 to I6-C13), and it removes none of the eight. Nothing in the Inject 06 artefacts excludes anything that Inject 04 left open.

## 19. Logging and Investigation Limitations

Inject 06 asks for exactness: which questions are unanswerable, which log source would have answered them, and whether the data never existed or has aged out. Those are different failures with different fixes, so every row carries a class.

| Class | Meaning | Fix is |
|---|---|---|
| **Never existed** | No control or log could have recorded it. | Build the control |
| **Not enabled** | The source can produce the data. It was off or not configured. | Turn it on (no retroactive recovery) |
| **Not forwarded** | The data exists on the system and never reached Sentinel. | Forward it |
| **Aged out** | It existed. Retention removed it. | Retention, or find a longer-lived copy |
| **Not supplied** | It exists and we have not been given it. | Ask |
| **Third party** | Another organisation holds it. | Ask under the contract |

**Gap status** says whether the class itself is documented by FinServe (**Confirmed**) or not yet known (**Unknown which**).

### 19.1 By missing evidence source

Each row names the question that cannot be answered, the log source that would have answered it, whether the data never existed, was not collected or has aged out, what that does to confidence, and the fix. The classes are the six defined above.

| ID | Missing source | Unanswered investigative question | Required log source | Never existed, not collected or aged out | Impact on confidence and conclusions | Corrective action |
|---|---|---|---|---|---|---|
| S1 | **SFTP host logs** | What did each of the eleven sessions do, and did any begin before Sat 17 Oct 22:04:11? | `auth.log` and the `sftp-server` log on `sftp-slo`, rotated files, backups | **Not collected** for the weekend (local only, 30 days, no forwarder, E7 §3). **Aged out** for anything before the log's first line. | We hold two sessions of eleven. "Host activity began on Saturday 17 October" is limited to the extract. Host-side claims are reliable enough to act on, not to rely on (13.3). | Copy now with hashes (ER-01). Hold backup restore points (ER-04). Forward both logs to Sentinel after imaging (C-13). |
| S2 | **Host process, shell and connection history** | What started the 04:11 connection? | `auditd` or process accounting, shell history, EDR on `sftp-slo` | **Never existed.** None is documented, and the FinRecon host has no security logging (E7 §3). | X1 to X4 cannot be separated from the host side. Only the baseline and the image can help. | Capture live state and image the host (ER-02, ER-03). Add host audit logging after imaging. |
| S3 | **SQL audit logs for `sqldb-uat`** | Did a login succeed, as whom, what ran and what came back? | Azure SQL auditing, to storage or Log Analytics | **Not collected** into Sentinel (confirmed, E7 §1). **Never existed** if auditing was never enabled. Which one is **unknown**. | Database access can be neither confirmed nor excluded. The severity rests on potential impact and not on what happened. | Read the auditing configuration now (ER-09). Enable auditing to a destination Sentinel reads and connect the connector (C-14). |
| S4 | **Azure Firewall logs** | Is the 04:11 pattern new or nightly, and are three rows the whole picture? | `AZFWNetworkRule` in `law-sentinel-prod` (60 days, E7 §4) | **Collected.** Not supplied. The oldest day rolls off daily. | The best-protected evidence we hold. Without a baseline, X2 cannot be weighed against X1. | Run Q12 and Q13 today (ER-05). Export the rule definition before anyone edits it (ER-08). |
| S5 | **Storage diagnostics** | Did data leave `sqldb-uat` or the estate through a storage account? | `StorageBlobLogs` on the relevant storage accounts | **Never existed.** Diagnostics are off (E7 §1; I6-A4). | The blob route can never be excluded or confirmed for this period. Platform metrics show volume only. | Take the metrics (ER-17). Enable diagnostics for the future (Coverage-Gaps G2 and G7). |
| S6 | **Entra ID sign-in and audit logs** | Did the M365 session continue after 08:23:02, was it revoked, and did the address touch anything else? | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `OfficeActivity` (60 days in Sentinel; 30 days raw in Entra; Unified Audit Log 90 or 180 days) | **Collected.** Not supplied. Raw Entra data older than about 19 Sep has **aged out** as of 19 Oct. | The M365 side after 08:23:02 is unknown. Whether the stolen session survived revocation is unknown. | Run the Inject 04 queries and Q15 today (ER-15, ER-19). |
| S7 | **Sentinel ingestion and connector status** | For each "no results", is the source quiet or absent? | Connectors page, `Usage`, `Heartbeat`, data collection rules | **Not collected** for the host and the SQL audit (never onboarded). Fortigate is partial. The status itself is **not supplied**. | Absences cannot be classed. A source that has gone quiet looks like a clean one (E7 §5). | Export connector status and last-seen per table (ER-20, Q14, Q17). Add an ingestion-gap alert (Section 28, row 10). |
| S8 | **Fortigate DC-SLO traffic logs and policy** | How did 45.83.220.61 reach the host, and did data leave toward the internet? | FGT-SLO policy, NAT and traffic logs. Only facilities local0, auth and authpriv reach Sentinel (E7 §2). | **Not collected** (traffic logs not shown to arrive). Device-local retention unknown, so **possibly aged out**. | P5 stays an inference, and the internet-egress route cannot be assessed. | Show what arrives (ER-06) and export the policy and device logs (ER-07). |
| S9 | **Meridian's platform logs** | When did the address first use the account, and what was retrieved? | Meridian's SFTP platform | **Third party.** Retention unknown. | The only direct record of the actor using the credential, and the only source that may reach "February". | Ask under the contract, today, through the CISO (ER-13). |

### 19.2 By question

| # | Question | Why it cannot be answered now | Source that would answer it | Class | Gap status | Corrective action |
|---|---|---|---|---|---|---|
| 1 | What did the 04:11 connection do (login success, account, statements, rows returned)? | `SQLSecurityAuditEvents` returns no rows for `sqldb-uat`. The Azure SQL audit connector is not connected (E7 §1). Whether auditing is enabled on `sqldb-uat` at all is not documented. E7 §3 records auditing as on only for the managed instance, writing to storage. | Azure SQL auditing, to storage or Log Analytics | Not forwarded (to Sentinel), **or** Not enabled, **or** Not supplied (exists elsewhere) | Not forwarded: **Confirmed.** Which of the others: **Unknown.** | ER-09. Enable auditing to a destination Sentinel reads and connect the connector (raised twice, I6-A4). |
| 2 | Who or what on the host started the connection? | The `sftp-server` log shows SFTP operations only. No process accounting, EDR or shell history is documented for this host, and the separate FinRecon application host has no security logging either (E7 §3). The host's OS and logging are Unknown (Coverage-Gaps Q8). | `auditd` or process accounting, shell history, EDR, a host image | Not enabled, or Not supplied | **Unknown which** | ER-02, ER-03. Add host audit logging after imaging. |
| 3 | Did data leave `sqldb-uat` through a storage account or export? | Storage diagnostics are off (E7 §3; I6-A4). Data-plane operations were never recorded and cannot be recovered. | Storage diagnostic logs | **Not enabled** | **Confirmed** | ER-17 gives volume indicators only. Enable diagnostics in `sub-nonprod` (G2, G7). |
| 4 | Did data leave the Slough estate to the internet, and how much? | Fortigate syslog reaches Sentinel for facilities local0, auth and authpriv only (E7 §2). Whether traffic logs are among them is not documented. Device-local retention is not documented. | FGT-SLO traffic logs | Not forwarded or Not enabled. Aged out if device logs have rolled. | **Unknown which** | ER-06, ER-07. |
| 5 | Was the actor on the host before W2 D6 22:04:11? | Only an extract was supplied. | Full `auth.log`, rotated files, backups | From the log's first line to W2 D6: **Not supplied.** Before the first line: **Aged out** (30 days local, no forwarder, E7 §3). | Aged out: **Confirmed.** Backups: **Unknown.** | ER-01 and ER-04. |
| 6 | Did anything happen "since February"? | Nothing FinServe holds reaches that far on any relevant surface (Section 20). | Meridian's platform logs, if retained. Backups cover about 90 days. | Aged out (FinServe). Third party (Meridian). | FinServe: **Confirmed.** Meridian: **Unknown.** | ER-13, ER-04. The 365-day extension (about £31,000 a year, not approved, E7 §4) is a recorded decision whose consequence is this row. |
| 7 | How did the actor get the credential (P4)? | No log records knowledge passing. File contents unseen. | Document review and version history, Meridian's first-use time, failed-login pattern | Not supplied. Third party (Meridian). | **Unknown which** | ER-14, ER-13, ER-01. |
| 8 | How did 45.83.220.61 reach the host (P5)? | No FGT-SLO policy, NAT or traffic data supplied. Azure Firewall does not see inbound internet traffic to DC-SLO. | FGT-SLO policy and NAT configuration, traffic logs | Not supplied (configuration). Traffic logs: see row 4. | **Unknown which** | ER-06, ER-07. |
| 9 | What is in the six files (two on SharePoint, four on the host)? | Not supplied. I have not inferred contents from names. | SharePoint content and version history; host files or image | Not supplied | **Confirmed** (they exist) | ER-14, ER-02, ER-03, ER-10. |
| 10 | What did the nine unseen sessions do, including writes, renames, deletes? | Described, not shown. | Full `sftp-server` log | Not supplied | **Confirmed** | ER-01. |
| 11 | Were settlement files or deliveries altered? | No file integrity monitoring is documented. The extract shows read requests only. Delivered content is held by Meridian and Corebridge. | Write operations in the sftp log; control totals from Corebridge and Meridian | Not enabled (integrity monitoring). Not supplied. Third party. | **Unknown which** | ER-01, ER-13, and action C-11. |
| 12 | Do Meridian's counts match the host's, and what did Meridian say was retrieved? | Different platforms, no timestamps (T8). | Meridian's log | Third party | **Confirmed** | ER-13. |
| 13 | Did the M365 session continue after 08:23:02 on W2 D1? | Only the Inject 04 extract was supplied. | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `OfficeActivity` (60 days); Unified Audit Log | Not supplied | **Confirmed** (the data exists) | ER-15, Q2, Q15. |
| 14 | Do the host's clock and the Azure clock agree (T6)? | Syslog has no zone. | Host time zone and NTP status; a host-side record of the 04:11 connection | Not supplied | **Confirmed** | ER-01, ER-02. |
| 15 | Has anyone authorised ever used 45.83.220.61? | Organisational knowledge, not a log. | Named owners | Not supplied | **Confirmed** | ER-16. |

**Reading the table.** Rows 1 to 4 are about what the actor did with access. They are mostly telemetry that was never forwarded or never enabled, and that is what Marcus said he could not see. Rows 5, 6 and 13 are about how far back and how long. Only row 6 is truly gone, and only row 3 can never be recovered (the data was never created). Everything else is recoverable if it is asked for in time. That is why Section 23 is ordered by expiry.

> **Update (Inject 07):** row 1 of 19.2 now has a specific mechanism behind it (a credential in the script) and a second system (`sqlmi-prod`) that cannot be excluded. Row 9 shrinks by one file: the script is known from an extract. Eleven new items are in Section 32.4.3. UAT-side evidence for 18 October has a hard limit of Sunday 25 October 04:11 UTC.

## 20. Earliest Possible Compromise

Inject 06 asks for the earliest compromise that cannot be ruled out, not the earliest that can be seen. The two differ because FinServe's visibility does not cover the Slough estate and its retention is short.

### 20.1 Earliest confirmed malicious activity

| System | Earliest event | Basis | Status |
|---|---|---|---|
| M365 | Mon 12 Oct 07:59:44, the first session from 45.83.220.61 (A2) | A session from a hosting network, between two corporate sessions, with an MFA claim, 1 m 44 s after Rachel's "done" | **Assessed as unauthorised, high confidence.** Not confirmed in the strict sense: Q1 and Rachel's own account are not in hand. |
| DC-SLO host | Sat 17 Oct 22:04:11, the first logged login (I6-A2) | A login from an address Meridian does not allow-list | **Assessed as unauthorised.** Nobody has yet confirmed the address is not an authorised source (ER-16). |
| Meridian | Not stated ("over the weekend") | I6-A1 | Times **unknown** |

### 20.2 Earliest date compromise cannot be ruled out

This depends on the surface. Each horizon moves forward one day every day. As of Monday 19 October:

| Surface | Oldest data held | What it could exclude | Source |
|---|---|---|---|
| Sentinel tables (sign-ins, `OfficeActivity`, Azure Firewall, Fortigate syslog) | about Thu 20 Aug (60 days) | Use of this address in M365, or flows involving it through Azure Firewall or FGT-SLO, back to 20 Aug | E7 §1, §4 |
| Entra sign-in logs, raw | about Sat 19 Sep (30 days) | The same, for a shorter window | Section 5.3 row 4 |
| Unified Audit Log | about 22 Apr (180 days) or about 21 Jul (90 days), depending on licence | M365 activity by account | Section 5.3 row 4 |
| Host `auth.log` | first line unknown: about 14 Sep, 21 Sep or 3 Oct (13.3) | Logins from the address; failed attempts | I6-A2, I6-A4, E7 §3 |
| DC-SLO backup appliance | about 21 Jul (90 days), **only if this host is protected** | Earlier host logs | E7 §3 |
| Meridian's platform | unknown | The only source that may reach "February" | none |
| `sqldb-uat` point-in-time restore | 7 days | Object and permission changes only, not reads | E2 §3 |
| `sqldb-uat` audit | unknown, may not exist | Reads and statements, if it exists | Section 19, row 1 |
| Azure Monitor platform metrics | about 93 days (T12) | Coarse volume anomalies | T12 |

My answer, surface by surface:

- **M365.** Q2 settles it for 60 days. If Q2 finds nothing before 12 October, use of this address in M365 started on 12 October **within that window** and says nothing about other addresses.
- **Host.** From the log's first line, if the full `auth.log` shows nothing earlier from the address. Before that, only backups can speak, to about 21 July, and only if the host is protected.
- **The Meridian credential.** 2019. It has been static since the arrangement began and a plaintext copy sits in architecture documentation (E4 §4; Coverage-Gaps G3). That is exposure, not evidence of use.
- **Anything older, or from other addresses.** Cannot be excluded, because no retained data covers it.

### 20.3 Why these dates differ

- **The 12 October date is where visibility begins, not where the intrusion begins.** The host was never visible. The credential is old. The retention that would settle it was a budget decision (E7 §4).
- **Earliest plausible is earlier than earliest confirmed.** The credential capture that the lure makes plausible was at about 07:52 on 12 October, with preparation before it for an unknown period (the lookalike domain existed). Weak signals of earlier knowledge are the inbox-rule keywords (L5) and the host path foreknowledge (L3). Confidence **low**.
- **Proportion.** I rate a start on 12 October as the best-supported reading and I have **no positive evidence of anything earlier**. I report the horizons as limits on what can be excluded, not as findings. They are not a claim that an earlier start happened.
- **A past event of the same shape.** SEC-2025-03 (June 2025) was an invoice phish with one credential entry and a reset within four hours. Its action 4, whether a reset ends the attacker's session, is still open (E10 §4). I have no evidence linking it to this incident and I do not extend the window because of it. It is a reason to answer the question.

### 20.4 Evidence supporting the assessment

| Question | Answer | Basis | Class |
|---|---|---|---|
| **Earliest observed** (an artefact shows an event) | M365: Mon 12 Oct 07:59:44. Host: Sat 17 Oct 22:04:11. Meridian: not stated. | A2; I6-A2; I6-A1 | **[F]** for the events. That the actor did them is **[A]**. |
| **Earliest plausible** | Mon 12 Oct about 07:52, with preparation before it for an unknown period. | A1, A3, I6-A2 | **[A]**, low |
| **Earliest not excludable** | Depends on the surface (20.2). For exposure of the Meridian credential, 2019. | E4 §4; Coverage-Gaps G3 | **[F]** static since 2019 |

**To Marcus:** the weekend is what we can see. The weekend is not what we can say.

## 21. Severity Reassessment

### 21.1 Scope of the Slough activity

- **Established [F]:** Logged password logins by `finserve_settle` from 45.83.220.61 (two shown, nine described). Read requests for four files. Three permitted flows to `sqldb-uat` port 1433. A third-party report of the same address on Meridian's platform.
- **Assessed [A]:** The same operator as the M365 stage (Section 14). The Meridian delivery credential should be treated as exposed, because `deliver.cfg` is documented as holding it (E4 §4) and the actor requested it. The account on the host is not confined to its delivery directories **if** the `/opt/finrecon/conf` requests succeeded, which the extract does not show.
- **Cannot rule out:** Section 19 in full, in particular what the 04:11 connection did, the nine sessions, writes to settlement files, activity before W2 D6, data leaving the estate, and other DC-SLO workloads using the same account or credential.

### 21.2 Severity: Critical

- Assessed unauthorised access to a production settlement host in a legacy estate that Sentinel cannot see, over at least two days.
- A static credential, unrotated since 2019, was requested and must be treated as exposed.
- A permitted path from that host to a database copy of production that holds unmasked account numbers, balances, transaction history and National Insurance numbers (E2 §3). The effect on that database is unknown.
- A live third-party impact: Meridian has suspended the account and tonight's settlement will not deliver.
- Detection by a third party, 33 hours after the first logged login. The documents show no telemetry from the host and no database audit telemetry for `sqldb-uat`.

**Not claimed:** confirmed exfiltration, a confirmed read of `sqldb-uat`, a confirmed alteration of settlement data, or any activity before 12 October. The rating rests on potential impact and on what cannot be excluded, as in Section 6.

**What would lower it to High:** the full logs show only the eleven sessions, all reads limited to settlement files, the 04:11 flows fall in a nightly baseline (X2), and Meridian's logs show retrieval of nothing beyond FinServe's own deliveries. **What would raise it further:** a confirmed read of `sqldb-uat`, any write, rename or delete in settlement directories, a second host, or activity before 12 October. FinServe's own severity scale has not been provided (Section 11, question 6).

> **Update (Inject 07):** the conditions for lowering the rating to High, in 21.2 above, could not be met as written, because the actor's reads already went beyond settlement files. They are replaced in Section 32.6.

### 21.3 Should the severity change?

**Yes: from High (provisional) to Critical.** Section 6 named the trigger: "the SFTP logs show an unfamiliar login". They do (I6-P4). The statement in Section 6 that there was no evidence of use of the Slough access is withdrawn (Section 26).

### 21.4 Why the new database exposure changes the potential impact

In Inject 04 the potential impact was settlement fraud and reconnaissance of a legacy estate. The 04:11 connection adds a database that is documented as a nightly copy of production holding unmasked account numbers, balances, transaction history and National Insurance numbers (E2 §3), which are categories D2 and D3, both Restricted (E4 §1), for about 180,000 subjects and about 215,000 accounts. The effect on that database is unknown, but the potential moves from one settlement process to bulk customer data. The ceiling is not an estimate of what was accessed. No read is evidenced.

### 21.5 How missing audit evidence affects confidence

Confidence in the **rating** is high, because it rests on potential impact and on what cannot be excluded, as in Section 6. Confidence in **what happened** is low, and it stays low until the sources in Section 19.1 are read: S3 (SQL audit), S1 (the full host log), S4 (the baseline) and S9 (Meridian). If a SQL audit record existed the rating could go down or up. Its absence does not lower the rating, because an empty source cannot exonerate anyone (17.3).

### 21.6 Date of reassessment

**Monday 19 October 2026 (W3 D1)**, after Meridian's email at 07:12 and Marcus's reply at 07:31 UTC. Previous rating: High, provisional, Wednesday 14 October (Section 6).

## 22. Containment and Recovery Plan

The account is suspended by Meridian and tonight's file will not deliver, so the business impact has already landed. That changes the cost of containing the host: the main thing it still costs is tonight's 23:30 extract, which has nowhere useful to go while the account is suspended.

Times are relative to this report's release on W3 D1, after 07:31 UTC (T+0). Owners are roles from E6 `04-Stakeholders.md`. "(to be confirmed)" means ownership is not documented.

### 22.1 Rules this plan follows

1. **The old credential does not come back for the deadline.** It is treated as exposed. Reinstating it to meet the settlement window recreates the access.
2. **Preserve before change.** Anything that restarts, rebuilds or rotates comes after the copy.
3. **Restrict, don't rebuild.** Cut the access path at the network and leave the host powered, so memory and disk state survive until it is imaged.
4. **No alternative settlement route is assumed.** The only fallback is the one E6 §4 documents. Whether it may be used is the business's call.
5. **Delete nothing.** Disable and deny. Do not remove rules, accounts or files.

### 22.2 Prioritised actions

> **Update (Inject 07):** actions C-17 to C-33 are added in Section 32.8. C-08 (item 3), C-09, C-10 and C-14 are sharpened or replaced there. C-10 moves from P2 to P1, with the hard limit unchanged (Sunday 25 October 04:11). C-07 is brought forward: the CISO and GRC are told today.

| Priority | Action | Owner | Timing | Rationale | Dependencies | Completion criteria |
|---|---|---|---|---|---|---|
| **P1** C-01 | **Account.** Keep `finserve_settle` suspended. Reply to Meridian: acknowledge, state FinServe has not authorised the activity **once ER-16 confirms that**, say the account will not be reinstated on the existing credential, ask Meridian to preserve its logs and send them (ER-13), share the address. | CISO (Priya Raman) with Nadia Ferreira | T+0 to T+60 min | Meridian asked FinServe to confirm whether the activity is authorised. A wrong "authorised" or silence both cost more than a short holding reply. | ER-16 yes/no on the address. Known Meridian contact (to be confirmed). | Written reply sent by a known channel. Meridian confirms receipt and log preservation. |
| **P1** C-02 | **Credential.** The old Meridian credential is never reinstated. Reinstatement requires C-08, C-04 and C-05 and a Meridian-agreed supervised first run. | CISO decision; Meridian | Standing | Section 22.1, rule 1. | none | Written decision recorded. |
| **P1** C-03 | **Evidence first on the host.** Hash and copy the logs (ER-01), capture live state and configuration (ER-02), place a retention hold on backup restore points (ER-04). | Infrastructure, Tobi Okonkwo (to be confirmed), with SOC present | T+0 to T+60 min | The logs roll daily at their oldest end. Tobi Okonkwo leaves in about eight weeks and holds the deepest Slough knowledge (E6). | Host administrator access | Hashes recorded. Copies off-host. Custody log started. |
| **P1** C-04 | **Host: restrict at the network.** On FGT-SLO, allow inbound to 172.20.14.30 only from the documented Corebridge source(s), deny all other inbound, deny 172.20.14.30 to 10.30.2.14 and to any Azure destination not documented, log all denies. Export the current policy first (ER-07). Do not power off. | Network or Infrastructure (to be confirmed); CISO approves | T+30 to T+90 min, after the policy export | Cuts P5 and the 04:11 path while keeping volatile state. Cost: if Corebridge's source is not allowed, the 23:30 extract fails. | ER-07. Corebridge source addresses. | Test from outside shows no SSH. Deny counters visible. |
| **P1** C-05 | **Host: image it.** Disk snapshot and, if the platform allows without a restart, memory. The platform is not documented (Coverage-Gaps Q8), so the method is unknown. | Infrastructure or the co-location provider (to be confirmed) | Before 18:00 | Needed before any rebuild or credential change on the host. | Platform knowledge | Image hash recorded. Stored write-once. Access limited. |
| **P1** C-06 | **Business.** Decision on tonight (Section 22.3) taken by Finance Operations, the CFO and the CISO. Meridian told in time. | Nadia Ferreira (P8 owner), CFO Yusuf Karim, CISO | This afternoon | A late notice of a failed delivery costs Meridian and FinServe more than an early one. | C-01 | Decision recorded. Meridian informed. |
| **P1** C-07 | **GRC.** Section 27 to GRC tomorrow morning. CISO told today that it is going. DPO (Chinelo Nwosu) given the facts today if the CISO agrees. | SOC team, CISO | Today for the CISO, tomorrow morning for GRC | Notification and assessment decisions should not wait for the evidence to close. | none | Section 27 delivered. |
| **P2** C-08 | **Credential response**, in this order: (1) the host-local `finserve_settle` password, disabled or rotated after imaging; (2) the Meridian-side credential, replaced by Meridian, issued out of band to a named FinServe custodian only after C-03, C-04 and C-05, with the allowlist updated; (3) any credential found in the two SharePoint files, `deliver.cfg` or `refresh_uat.ps1` (ER-14, ER-10), rotated by reach: Slough hosts, then SQL, then the rest; (4) remove the plaintext value from architecture documentation and treat existing copies as exposed. Key-based authentication, which Meridian recommended in 2024, needs a FinRecon change by Solvex (E4 §4), so it is a recovery item and not a tonight item. | Infrastructure; Meridian; Solvex for the key change | (1) today after imaging; (2) when Meridian is ready; (3) as found; (4) this week | The credential has been static since 2019 and was requested by the actor. | C-03, C-05, ER-14 | Each rotation logged. Old values dead. Allowlist matches. |
| **P2** C-09 | **Database path.** Add an Azure Firewall deny, higher priority than the Allow, for 172.20.14.30 to 10.30.2.14:1433. Keep rule `CHG-2025-0132-dev-fileshare`. Export the policy and rule definition first (ER-08). Then find out why the rule matches DC-SLO traffic. | Cloud platform or network (to be confirmed) | Today | The Allow matched traffic outside its documented purpose (E1 §3.1: Dev subnet to the shared-services file server). | ER-08 | Deny hit counts visible. No DC-SLO flows to 10.30.2.14 other than documented ones. |
| **P2** C-10 | **Database state.** Point-in-time restore of `sqldb-uat` to about W2 D7 04:20 into an isolated database, and keep deleted-database backups. Pause or check tonight's 02:00 refresh (F10). | DBA or cloud platform (to be confirmed) | W3 D1 to W3 D3. Hard limit about Sun 25 Oct 04:11. | The only database-side state still recoverable where no audit exists (ER-12). | ER-10, ER-12 | Restore exists, access-limited. |
| **P2** C-11 | **Settlement integrity.** Ask Meridian for control totals or hashes of every delivery received since W2 D1, especially the nights of W2 D6 to D7 and W2 D7 to W3 D1. Finance Operations compares them with Corebridge's own totals and checks `/settlement/outbound` against Corebridge before any file is used. | Nadia Ferreira; Meridian; Corebridge (by ticket, about 5 working days) | Today | The actor had read access and may have had write access. A tampered file is a settlement-integrity risk. | ER-13 | Totals match, or the differences are explained. |
| **P2** C-12 | **M365 residuals.** Confirm that the Inject 04 actions were done: sessions revoked, account blocked, rule "." disabled, mailbox hold, MFA methods reviewed. Re-run Q1, Q2, Q7, Q15. | SOC | Today | The status of Inject 04 actions is not stated in any artefact. | ER-16 | Written confirmation. No sign-in from the address after revocation. |
| **P3** C-13 | **Visibility.** After imaging: forward `auth.log` and the sftp log to Sentinel (G3), set sshd to verbose logging, restrict SSH by source, confine the SFTP user to its delivery directories. | Infrastructure; Security Operations | W3 D3 to W3 D5 | Rows 1 and 2 of Section 19 must not recur. | C-05 | Logs visible in Sentinel. |
| **P3** C-14 | **Database visibility.** Enable auditing on `sqldb-uat` to a destination Sentinel reads. Connect the SQL audit connector. | Marcus Ifill; cloud platform | W3 D3 to W3 D5 | Raised twice already (I6-A4). | none | A test query returns audit rows. |
| **P4** C-15 | **Host future.** After forensic review, decide whether to rebuild or retire. DC-SLO is due to be decommissioned by end-2026 (E1 §8); consider accelerating for this host. | CTO (Elliot Vance); Head of Infrastructure | After review | Rebuilding earlier loses the evidence. | C-05 and review | Decision recorded. |
| **P4** C-16 | **Sweep.** Check the other DC-SLO workloads (11 remain, E1 §8) for internet reachability and for use of the same account or credential, while the Head of Infrastructure is still here. | Infrastructure | Within weeks | One internet-reachable host suggests others. | none | Inventory with exposure recorded. |

### 22.3 Settlement account

**Continued suspension or controlled restoration.** Keep `finserve_settle` suspended (C-01, C-02). Restoration is controlled and is not tonight's decision. It needs a replacement credential that Meridian issues out of band to a named FinServe custodian (C-08), a host that is restricted (C-04) and imaged (C-05) and preferably rebuilt after review (C-15), an updated allowlist at Meridian, and a supervised first run that Meridian agrees to.

**Coordination with Meridian.** One holding reply today (C-01): acknowledge, state that FinServe has not authorised the activity **once ER-16 confirms that**, say the account will not return on the existing credential, ask Meridian to preserve and send its logs (ER-13), and share the address. Then agree with Meridian: delivery outside the 00:00 to 01:00 window if the manual route is used, control totals for every delivery since Monday 12 October (C-11), and the contract's incident-notice terms (Question 17).

**Conditions for safe reactivation.** All of these, in writing:

1. The old credential is dead on both sides, and the new one is held by a named custodian (C-08).
2. The host is restricted at the network and imaged, and a decision on rebuild or retire is recorded (C-04, C-05, C-15).
3. The SFTP account is confined to its delivery directories, SSH is restricted by source, and host logs reach Sentinel (C-13).
4. Meridian's allowlist matches FinServe's documented sources.
5. Control totals for the nights since Monday 12 October match Corebridge's (C-11).
6. The first run is supervised by Finance Operations and Meridian, and the SOC watches the host log while it runs.

**Tonight's settlement**

The decision belongs to Finance Operations (Nadia Ferreira, P8 owner), the CFO and the CISO. The SOC's position:

| Option | What it is | SOC position |
|---|---|---|
| **A. Hold the cycle** | No delivery tonight. Meridian is told. The 07:00 reconciliation report will not arrive (E6 §4). | **Safest.** P8 is not on the important business services list (E6 §4). The impact is known and bounded. |
| **B. Documented manual fallback** | Finance Operations produce and deliver the file by hand. E6 §4: about four hours, used twice, most recently in 2024. The document does not say through which channel it delivers. | **Only on these conditions, none of which I can assume:** (1) Nadia names the delivery channel and Meridian agrees to it and to delivery outside the 00:00 to 01:00 window if needed; (2) the channel does not use `finserve_settle`, `deliver.cfg` or the host's SFTP service; (3) the source file comes from Corebridge or another trusted source, or its control totals are verified against Corebridge's before it is sent; (4) it is prepared on a device and account not involved in this incident; (5) the CISO and CFO accept the residual risk in writing. |
| **C. Restore the automated path tonight** | Reinstate the account and the scheduled delivery. | **Not recommended.** It needs a replacement credential from Meridian, a trusted host, an updated allowlist and a supervised first run. None is achievable safely today. |

Because the fallback takes about four hours and tonight's extract arrives at 23:30 (E4 §4), the 00:00 to 01:00 window is unlikely to be met by Option B **[A]**. Meridian's agreement to late delivery is part of condition 1.

### 22.4 SFTP host

**Isolation or restriction.** Cut the access path at the network and leave the host powered, so that memory and disk state survive until it is imaged (C-04). Deny the host's route to `sqldb-uat` (C-09). Do not power off, restart or patch it.

**Evidence preservation.** Everything in Section 23.1 is copied, hashed and logged before any change to the host. Anything that restarts, rebuilds or rotates a credential on the host comes after the copy (rule 2 in 22.1).

**Investigation before rebuild.** Image the host (C-05), review the image and the logs, and sweep the other DC-SLO workloads for exposure and for use of the same account (C-16). Only then decide whether to rebuild or retire the host. DC-SLO is due to be decommissioned by the end of 2026 (E1 §8), so retiring it sooner is an option (C-15). Rebuilding first loses the evidence.

### 22.5 Credentials

**Rotation.** In the order in C-08: the host-local `finserve_settle` password after imaging; the Meridian-side credential, replaced by Meridian and issued out of band; any credential found in the SharePoint files, `deliver.cfg` or `refresh_uat.ps1`, rotated by reach (Slough hosts, then SQL, then the rest); and the plaintext value removed from architecture documentation, with existing copies treated as exposed. Not before imaging (22.7).

**Review of exposed service credentials.** The credentials that must be reviewed are those the actor asked to open or could have learned of: the Meridian delivery credential in `deliver.cfg` (documented, E4 §4); whatever `refresh_uat.ps1` connects to and as which account (contents **unknown**, so a named reviewer reads it and reports, ER-10); anything in `DR-SLO access notes.txt` and `Settlement runbook v4.docx` (ER-14); and every other file in `/opt/finrecon/conf`, because the actor listed that directory and its file names are therefore known to them.

**Preventing shared credentials between production and UAT.** The host reached UAT SQL, and UAT is a copy of production (E2 §3). What the connection used is unknown, and so is whether the refresh script shares a credential across the two zones. The control is the same either way, and it is applied once ER-10 answers: no credential is valid in both zones; each environment and each purpose has its own account; secrets come from Key Vault and not from scripts; the account that reads production cannot write UAT, and the reverse. The network side is the deny in C-09 and a review of the standing production and non-production exceptions, because CHG-2024-0881 has no expiry (Section 28, row 6).

### 22.6 Business continuity

**Secure restoration of settlement delivery.** The documented fallback is the manual route in E6 §4 (Option B in 22.3). The target state is the automated path restored on a new credential, key-based authentication (which Meridian recommended in 2024 and which needs a FinRecon change by Solvex, E4 §4), a trusted host, and the validations above.

**Business risk of continued suspension.** Each cycle that is missed means no delivery to Meridian and no 07:00 reconciliation report (E6 §4). P8 is not on the important business services list (E6 §4), so the impact is bounded today, and it grows with each missed cycle. The SOC cannot size it. Finance Operations and Meridian can (Questions 17 and 20).

**Approval and validation requirements.** Finance Operations (Nadia Ferreira, P8 owner), the CFO and the CISO approve any manual delivery and any reinstatement, in writing. Meridian agrees in writing to any late delivery and to the supervised first run. Validation is the six conditions above, signed off by the SOC for the host and by Finance Operations for the totals.

### 22.7 What I am not recommending

- Reinstating the account or the old credential to meet the deadline.
- Rotating the credential on the host before it is imaged.
- Powering off or rebuilding the host first.
- Deleting the firewall rule, the account or the files.
- Blocking 45.83.220.61 and treating that as containment. Blocking the address is worth doing and proves nothing about other infrastructure.
- Contacting the address or probing it.
- Any settlement route that is not already documented.

## 23. Evidence Preservation

Everything below is copied, hashed with SHA-256 before and after, stored write-once off the system examined, and recorded in a custody log (the template is in `INC-01-Evidence-Requests.md`, Section 7) before anyone rebuilds, restarts, patches or rotates anything. Ordered by how soon each item is lost.

### 23.1 On the SFTP host, before any rebuild or change

| Item | Why it must be preserved | Lost when | Request |
|---|---|---|---|
| `auth.log`, rotated files and the sftp log | The only record of host sessions. We hold two of eleven. | Daily: the oldest lines roll off at 30 days | ER-01 |
| Live state: sessions, processes, sockets, timers, accounts, configuration | Shows what is running now, what is connected and what is scheduled, including anything planted. | On any restart | ER-02 |
| Disk image and, if the platform allows it without a restart, memory | Everything else about the host, and the basis for any later review. | On any rebuild, patch or restart | ER-03 |
| `deliver.cfg`, `refresh_uat.ps1` and the rest of `/opt/finrecon/conf`: hashes, owner, mode and file times | Shows what the actor asked to open and whether it has changed since. | On any edit or rotation | ER-02, ER-10 |
| Backup restore points for the host | The only source of host history before the log's first line. | Daily: the oldest roll off at 90 days | ER-04 |
| The custody log | Without it nothing above can be relied on later. | Start now | all |

### 23.2 Elsewhere, expiring or changed by containment

| Item | Why it must be preserved | Lost when | Request |
|---|---|---|---|
| Sentinel exports (Azure Firewall, Fortigate) | The baseline for the 04:11 flows and the Fortigate view of the address. | Daily: the oldest of 60 days rolls off | ER-05, ER-06 |
| FGT-SLO configuration and device logs | How the address reached the host, and any egress. | Unknown for device-local logs. Containment edits overwrite configuration. | ER-07 |
| Azure Firewall policy and rule history | Containment changes overwrite what the rule looked like. | On any rule edit | ER-08 |
| Meridian's logs | The only direct record of the actor using the credential. | Third-party retention unknown | ER-13 |
| `sqldb-uat` point-in-time state | Where no audit exists, database state can still show new principals or objects. | About Sun 25 Oct 04:11. Tonight's 02:00 refresh may replace the database. | ER-12 |
| SharePoint version history for the two files | Edits to the files overwrite what they held. | On any edit | ER-14 |
| M365 sign-in and audit data for the address | Whether the stolen session continued. | Daily: oldest of 60 days (30 days raw in Entra) | ER-15, ER-19 |

## 24. Recommendations and Next Steps

Each recommendation names the finding it answers and how. Action IDs (C-xx) are in Section 22.2. Request IDs (ER-xx) are in `INC-01-Evidence-Requests.md`.

### 24.1 Immediate containment (today)

| Recommendation | Finding it answers | How it helps | Owner |
|---|---|---|---|
| Keep `finserve_settle` suspended and reply to Meridian once ER-16 confirms the address is not authorised (C-01, C-02). | The credential is treated as exposed (I6-L3) and Meridian asked for a response. | Stops reinstatement on the old credential, and puts FinServe's position on record. | CISO with Nadia Ferreira |
| Copy and hash the host logs, capture live state, hold backup restore points (C-03). | S1 and S2 in 19.1: the logs roll daily and the state is lost on restart. | Keeps the only record of the host sessions. | Infrastructure with the SOC present |
| Restrict the host at the network, then image it (C-04, C-05). | P5: the host accepts SSH from the internet. | Cuts the route in and the route to the database while keeping volatile state. | Network or Infrastructure; CISO approves |
| Deny the host's route to `sqldb-uat` after exporting the rule (C-09). | I6-L6: the Allow rule is broader than its documented purpose. | Stops a repeat of the 04:11 path. | Cloud platform or network |
| Take the settlement decision for tonight (C-06) and tell the CISO and DPO today (C-07). | Live business impact; potential personal data. | Avoids a late failed delivery, and starts the notification decisions that are not the SOC's. | Finance Operations, CFO, CISO |

### 24.2 Investigation (24 to 72 hours)

| Recommendation | Finding it answers | How it helps | Owner |
|---|---|---|---|
| Run the baseline (Q12, Q13) and read the auditing configuration of `sqldb-uat` (ER-05, ER-09). | I6-C1: what the 04:11 connection was. | One query may show the flows are nightly. The configuration says whether a record exists anywhere. | Security Operations; DBA |
| Have a named reviewer say what `refresh_uat.ps1` and the two SharePoint files contain (ER-10, ER-14). | I6-C7 and I6-C9: the credential path and the contents. | Tests the one explanation we cannot otherwise test, without sending the files. | Infrastructure; SharePoint administrator |
| Read the full host log for failed attempts, other sessions and the first line (ER-01). | I6-C5 and I6-C10. | Settles whether this began at the weekend and what the nine unseen sessions did. | Infrastructure |
| Ask Meridian for its log and the first-use time (ER-13). | I6-C6 and I6-C7. | Shows whether the actor held the credential before the host read. | CISO |
| Re-run the M365 queries and confirm what was done after Inject 04 (ER-15, ER-16, ER-19, C-12). | I6-C12. | Shows whether the stolen session survived. | Security Operations |

### 24.3 Recovery (this week)

| Recommendation | Finding it answers | How it helps | Owner |
|---|---|---|---|
| Rotate credentials in the C-08 order, after imaging. | I6-L3 and the static credential since 2019 (E4 §4). | Ends the useful life of anything the actor requested. | Infrastructure; Meridian; Solvex |
| Check settlement integrity against Meridian's and Corebridge's control totals (C-11). | I6-C11: the actor had read access and may have had write access. | A tampered file is a settlement-integrity risk. | Nadia Ferreira; Meridian |
| Reinstate the automated path only when the six conditions in 22.3 are met. | Live business impact. | Restores delivery without recreating the access. | CISO, CFO, Finance Operations, Meridian |
| Decide whether to rebuild or retire the host after review (C-15). | The host was accessed by an unauthorised actor. | Removes any persistence without losing evidence first. | CTO; Head of Infrastructure |

### 24.4 Long-term security improvements

| Recommendation | Finding it answers | How it helps | Owner |
|---|---|---|---|
| Forward host logs to Sentinel, confine the SFTP account, restrict SSH by source (C-13). | S1: Slough was found by a third party after 33 hours. | Makes DET-06 able to fire. | Infrastructure; Security Operations |
| Enable SQL auditing on `sqldb-uat` to a destination Sentinel reads and connect the connector (C-14). | S3: the database cannot be characterised. | Makes the next event answerable. No retroactive effect. | Marcus Ifill; cloud platform |
| Remove static and plaintext credentials, move to key-based authentication, separate production and UAT accounts (C-08, 22.5). | The Meridian credential has been static since 2019. | Removes the credential the actor requested. | Infrastructure; Solvex |
| Review all standing firewall exceptions, and add the detections listed in Section 28, row 9. | I6-L6 and I6-L8. | Closes the over-broad rule and shortens time to detect. | Cloud platform; Security Operations |
| Sweep the other DC-SLO workloads (C-16) while the Head of Infrastructure is still here. | I6-C13. | One internet-reachable host suggests others. | Infrastructure |

## 25. References

### 25.1 Evidence used

| Ref | Artefact | Where it comes from |
|---|---|---|
| I6-A1 | Email from Operations Risk, Meridian Trust plc, Mon 19 Oct 07:12, to `settlement.ops@finserve.example`, cc the CISO | Inject 06, `05-INJECTS/Inject-06-Mailbox-Access.md` |
| I6-A2 | DC-SLO SFTP server local syslog extract, "retrieved by hand" | Inject 06 |
| I6-A3 | Azure Firewall rows from `law-sentinel-prod`, and the empty `SQLSecurityAuditEvents` query | Inject 06 |
| I6-A4 | Message from Marcus Ifill, Security Operations Manager, 07:31 | Inject 06 |
| A1 to A3 | Reported email and service desk notes (SD-2026-4417); Sentinel incident 2026-W2D1-0093; Unified Audit Log extract for `r.oduya` | Inject 04, `05-INJECTS/Inject-04-Invoice-Phish.md`, as transcribed in Sections 2 and 3 |

### 25.2 Project files used

E-numbers follow Section 2 of this report and Section 2 of `Coverage-Gaps.md`.

| Ref | File | Used for |
|---|---|---|
| E1 | `02-ARCHITECTURE/01-Network-Diagram.md` | §3.1 standing firewall exceptions; §6 telemetry; §8 DC-SLO decommission |
| E2 | `02-ARCHITECTURE/02-Azure-Architecture.md` | §3 data services and the UAT copy; §1 and §4 subscriptions and access; §7 telemetry |
| E4 | `02-ARCHITECTURE/04-Data-Flow.md` | §1 data categories; §2 flows; §4 the settlement path and `deliver.cfg` |
| E6 | `01-CLIENT/03-Business-Processes.md` (P8, §4); `01-CLIENT/04-Stakeholders.md` | Settlement process and fallback; owners |
| E7 | `04-SOC/Logs/Log-Source-Inventory.md` | Connectors, local logging, retention |
| E8 | `04-SOC/Alerts/Analytics-Rules.md` | Existing rules, including the non-functional CUST-03 |
| E9 | `04-SOC/Alerts/Alert-Summary-30-Days.md` | Alert workload |
| E10 | `04-SOC/Incident-Tickets/Incident-Log-2025.md` | SEC-2025-03 |
| E11 | `04-SOC/Threat-Intel/Threat-Profile-2025.md` | BEC against Finance |
| E12 | `04-SOC/IOCs/IOC-Register.md` | Indicators |
| | `06-DELIVERABLES/SOC/Coverage-Gaps.md` (G1 to G10, Q7, Q8); `Detection-Backlog.md` (DET-01, DET-03, DET-06, DET-10, DET-11); `Detection-Surface.md`; `socplan.md` | Gap ratings, detection backlog, the engagement plan and its early-escalation rule |
| | `INC-01-Evidence-Requests.md` (ER-01 to ER-20) | The requests this report relies on |

### 25.3 Evidence and files still required

| Still required | Why | Request |
|---|---|---|
| The full `auth.log`, rotated files and sftp log, with `close` lines and byte counts | Two of eleven sessions are shown. Completion and volume are unknown. | ER-01 |
| Meridian's log and allowlist for `finserve_settle` | The only direct record of the actor using the credential | ER-13 |
| `sqldb-uat` auditing configuration and any audit records | The only direct evidence of what the 04:11 connection did | ER-09 |
| The baseline of host-to-database flows, 60 days | Decides whether the 04:11 flows are new | ER-05 |
| Fortigate DC-SLO policy, NAT and traffic logs | How the address reached the host, and any egress | ER-06, ER-07 |
| What the two SharePoint files and `refresh_uat.ps1` contain, from a named reviewer | The credential path (P4) and the script's purpose | ER-14, ER-10 |
| M365 and Entra sign-in, session and audit data for the address | Whether the stolen session continued | ER-15, ER-19 |
| Sentinel connector and ingestion status | To class every "no results" | ER-20 |
| Asset register confirmation that 172.20.14.30 is `sftp-slo` and 10.30.2.14 is `sqldb-uat` | Every statement about the 04:11 flows depends on it (T11) | Question to FinServe |
| The host's time zone and clock status | The "nineteen minutes" depends on it (T6) | ER-01, ER-02 |
| FinServe's own incident severity scale | Section 11, question 6 is still open | Question to FinServe |
| The raw Inject 04 artefacts A1 to A3 | This report cites them as transcribed | Team |

## 26. What Changes in Sections 1 to 11

Inject 06 contradicts or extends the following Inject 04 conclusions. Each is also marked in place.

| Section | Earlier statement | Status now | Why |
|---|---|---|---|
| 1, Rating | "High, provisional", rising to Critical on specific triggers | **Superseded: Critical** | One named trigger, "the SFTP logs show an unfamiliar login", is met (I6-A2). |
| 1, Biggest unknown | The contents of the two files, and attacker activity after 08:23:02 | **Update** | Still unknown, and joined by the gap between the downloads and the host login (P4, P5) and by the 04:11 connection. |
| 3, last row | Attacker activity after 08:23:02 **[U]** | **Update** | Activity by the same address after 08:23:02 is now evidenced on the host. The M365 side after 08:23:02 is still **[U]**. |
| 5.2 | The goal is settlement-process reconnaissance leading to settlement fraud | **Revised** | The host reads and the database connection point at least as much to credential and data collection. I cannot rank the aims. |
| 5.3 row 3 | Use of the DR-SLO notes against Slough cannot be ruled out, and Sentinel cannot answer it | **Superseded in part** | Use of Slough access is now observed. Whether the notes were the source is still unknown. "Sentinel cannot answer it" stands: the host's local log is what answered. |
| 5.3 row 4 | Earlier compromise, 60-day horizon | **Update** | Per-surface horizons in Section 20. The host horizon is about mid-September. |
| 6, Severity | High, provisional. "No evidence so far of ... use of the Slough access." | **Superseded: Critical** | Same as above. |
| 7.2, last CISO decision row; 7.3 row 5 | Rotate the static SFTP credential before tonight's run | **Superseded** | Meridian has suspended the account and tonight will not deliver. The question is now how and when the account comes back, not whether to rotate before the run (Section 22). |
| 8, Q9 | Expected only the nightly delivery script's logins and no Fortigate flows involving the attacker's IP | **Contradicted** | The host shows eleven successful logins by `finserve_settle` from the address (two shown). |
| 9 | Detection gap focused on M365 | **Extended** | The larger gap is the Slough and database blind spot (Section 28). |
| 11, questions 2 and 7 | File contents; rotation procedure | **Open, extended** | See Section 30. |

**Unchanged:** Section 4 (the control stack for the M365 stage), 5.1, the first three bullets of 5.2, assumptions T1 to T4, and Section 7's M365 actions.

## 27. Handoff to GRC

### 27.1 My call

I am sending GRC this section tomorrow morning and telling the CISO today. Three reasons. The decisions GRC takes depend on dates and data classes that I hold now. The evidence that would settle scope may not close for days, and some of it may never close. A handoff that overstates what we know is worse than none, so it is written to be safe to rely on.

### 27.2 What GRC is getting

| GRC needs to know | What SOC can say | Basis | What GRC must not infer |
|---|---|---|---|
| **Is personal data in scope?** | **Possibly.** Candidate sources, none of whose contents I have seen: Rachel's mailbox and the Settlement Ops shared mailbox (accessed); the two SharePoint files (downloaded); two files in `/settlement/archive` (open requests logged); `sqldb-uat` (network flow permitted). | A3; I6-A2; I6-A3 | That any of it contained personal data, or that none did. |
| **What data classes could be in scope?** | The settlement flows F7 and F8 are documented as category D3 (account number, balance, transaction history; Restricted) (E4 §2). `sqldb-uat` is documented as holding unmasked account numbers, balances, transaction history and National Insurance numbers (E2 §3), which are D3 and D2 (E4 §1). | E4 §1, §2; E2 §3 | That the two archive files hold D3 data. I have not seen them, and the directory name is not their contents. |
| **How large could it be?** | The documented size of the categories is about 215,000 accounts (D3) and about 180,000 subjects (D2) (E4 §1). E2 §3 describes `sqldb-uat` as a refreshed copy of production. | E4 §1; E2 §3 | That this is an estimate of what was accessed. It is the ceiling if the whole database was read, and no read is evidenced. |
| **Key dates** | First unauthorised M365 session: 12 Oct 07:59:44 (assessed). Phishing reported: 12 Oct 08:31. Sentinel incident: 12 Oct 08:47. Inject 04 report: 14 Oct. First logged host login: 17 Oct 22:04:11. Permitted flows to `sqldb-uat`: 18 Oct 04:11:09. Meridian's alert: 19 Oct 07:12. | A1, A2, I6-A1 to I6-A3 | That 19 October is the date FinServe became aware. Whether and when a personal data breach was known is for the GC and DPO. The earliest candidate is not 19 October, because mailbox and file access by an unauthorised session was known from 12 October. Whether those held personal data is not known. |
| **What will settle scope, and when** | ER-14 (file contents): hours. ER-01 (host logs): hours. ER-09, ER-11 (database): hours to days. ER-13 (Meridian): days, third party. | Evidence Requests | That silence from SOC means no finding. |
| **Third parties** | Meridian Trust is the settlement counterparty and holds the platform where the account was used. It may have its own obligations. Solvex supports FinRecon with remote access from Bengaluru and is not on the supplier register (E6 `04-Stakeholders.md`; E4 §5). Corebridge holds logs by ticket, about five working days. | I6-A1; E4 | Anything about contractual duties, which SOC has not seen. |
| **Control facts GRC may use** | Static credential since 2019, and Meridian's 2024 recommendation to move to keys is unactioned (E4 §4). A plaintext copy in architecture documentation (Coverage-Gaps G3). UAT holds unmasked production data (E2 §3) and is reachable from DC-SLO through an Allow rule that exceeds its documented purpose (E1 §3.1). P8 is not an important business service although its failure tonight is a live impact (E6 §4). SEC-2025-03 actions 1, 2 and 4 are still open (E10 §4). | as cited | That these caused this incident. They are conditions it exploited or exposed. |
| **Decisions that are not SOC's** | Whether and when to notify the ICO, the FCA, Meridian or anyone else. Whether the P8 classification should change. Risk register entries. | | |

### 27.3 What SOC asks of GRC

- Name a GRC contact for daily updates until the evidence in Section 23 closes.
- Tell SOC if the DPO wants any evidence held in a particular form.
- Do not circulate logs or file contents outside the people who need them. Section 27 contains none.

> **Update (Inject 07):** the handoff is extended in Section 32.9. It adds the shared credential, the 181,402 records, the unmasked interval in UAT restore points, and the evidence that is still outstanding. It also states that the database in GRC's finding and the database in SOC's firewall log are the same database.

## 28. Detection and Control Gaps This Incident Shows

I have not changed `Coverage-Gaps.md` or `Detection-Backlog.md`, because Inject 06 does not ask for it and each file belongs to an earlier inject. The suggestions below are for the next revision.

| # | Gap | Where it showed up | Existing record | Suggested action |
|---|---|---|---|---|
| 1 | Host logs not in Sentinel | The Slough sessions were found by a third party after 33 hours. | G3 (rated High). DET-06 existed and could not fire. | Forward the logs (C-13). Re-rank G3. |
| 2 | Database audit not connected, UAT specifically | The 04:11 connection cannot be characterised. | G7 (Medium to High) and G1 | Enable auditing and connect (C-14). Re-rank G7. |
| 3 | Storage diagnostics off | Row 3 of Section 19 can never be answered. | G2, G7 | Enable diagnostics. |
| 4 | No visibility of third-party platforms, no route for partner alerts | Meridian's alert arrived by email to a shared mailbox. | G6 | Agree a partner alert path with named contacts. |
| 5 | Fortigate data collected, nothing watching it, and unclear which log types arrive | Step P5 and rows 4 and 8 of Section 19. | G5 | Settle what arrives (Q14). Write rules once it is known. |
| 6 | **New: an Allow rule wider than its documented purpose** | `CHG-2025-0132-dev-fileshare` permitted DC-SLO to UAT SQL. The documented purpose is Dev to a file server (E1 §3.1). | Not in Coverage-Gaps | Add a gap. Review all standing exceptions. CHG-2024-0881 also has no expiry date. |
| 7 | **New: SSH on the host apparently reachable from the internet** | Step P5 **[A]**. | Not in Coverage-Gaps | Confirm (ER-07), then add a gap. |
| 8 | Credential hygiene | Static since 2019, plaintext copies in documentation, an SFTP account able to request files in the application's configuration directory. | G3, E4 §4 | C-08, C-13. |
| 9 | Detections to write once telemetry exists | | | (a) Any `finserve_settle` login from outside the allowlist or the 23:30 to 01:00 window. (b) Any Azure Firewall flow from the DC-SLO range to non-production SQL. (c) First-seen source for a service account. All need telemetry first. |
| 10 | No monitoring of sources that go quiet | Cannot tell a quiet source from a clean one. | E7 §5 | Ingestion-gap alert. |

## 29. Queries and Commands Added by Inject 06

None has been run. There is no tenant or host access. Table and column names are as I understand the schemas and must be checked in the workspace. Everything here is read-only. These are the queries the Evidence Requests refer to.

**Q12. The host and `sqldb-uat` in Azure Firewall, 60 days (Sentinel)**

```kql
AZFWNetworkRule
| where TimeGenerated > ago(60d)
| where SourceIp == "172.20.14.30" or DestinationIp == "10.30.2.14"
| summarize Flows = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by SourceIp, DestinationIp, DestinationPort, Action, Rule, Hour = hourofday(TimeGenerated)
| order by First asc
```

*Expect:* either flows at consistent hours on earlier nights (the 04:11 flows are then in or out of a pattern, which weighs on X2) or only the W2 D7 04:11 rows (first ever, X2 loses weight). Only flows that cross Azure Firewall appear, and earlier rows reach back no further than 60 days.

**Q13. Everything that connects to `sqldb-uat` on 1433, 60 days (Sentinel)**

```kql
AZFWNetworkRule
| where TimeGenerated > ago(60d)
| where DestinationIp == "10.30.2.14" and DestinationPort == 1433
| summarize Flows = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by SourceIp, Rule, Action
| order by Flows desc
```

*Expect:* the legitimate sources and the rules they use. If 172.20.14.30 appears only on W2 D7, it is new behaviour.

**Q14. What the Fortigates send, and anything about the address or the host (Sentinel)**

```kql
Syslog
| where TimeGenerated > ago(7d)
| where Computer has "FGT-SLO"
| summarize Messages = count(), Sample = make_set(substring(SyslogMessage, 0, 120), 3) by Facility
```

```kql
Syslog
| where TimeGenerated > ago(60d)
| where Computer has "FGT-SLO"
| where SyslogMessage has_any ("45.83.220.61", "172.20.14.30")
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated asc
```

*Expect:* if the first query shows only event and authentication messages, traffic logs are not in Sentinel (Section 19, row 4). If the second shows inbound flows from the address to 172.20.14.30 on port 22, step P5 is evidenced.

**Q15. Everything the address did in M365 since W2 D1 (Sentinel)**

```kql
OfficeActivity
| where TimeGenerated > ago(60d)
| where ClientIP has "45.83.220.61"
| summarize Operations = make_set(Operation, 30), Users = make_set(UserId), First = min(TimeGenerated), Last = max(TimeGenerated)
    by OfficeWorkload
```

*Expect:* Rachel's activity on 12 October. A `Last` after 08:23:02 on W2 D1 means the actor kept M365 access. Any other user is another victim. Pair with Q2 for sign-ins.

**Q16. Who else touched the two documents (Sentinel, then the audit log)**

```kql
OfficeActivity
| where TimeGenerated > ago(60d)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where OfficeObjectId has_any ("DR-SLO access notes.txt", "Settlement runbook v4.docx")
| project TimeGenerated, UserId, Operation, ClientIP, UserAgent, OfficeObjectId
| order by TimeGenerated asc
```

```powershell
Search-UnifiedAuditLog -StartDate <today minus 180 days> -EndDate <now> -ObjectIds "*DR-SLO access notes.txt*" -ResultSize 5000
```

*Expect:* accesses by Finance and Infrastructure users from corporate addresses. An unfamiliar user or address, or an access before 12 October, moves H3 (Section 16.2).

**Q17. Which resources write SQL audit events to the workspace (Sentinel)**

```kql
SQLSecurityAuditEvents
| where TimeGenerated > ago(60d)
| summarize Events = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by _ResourceId
```

*Expect:* empty, or only the managed instance. A "failed to resolve table" error would mean no SQL audit data has ever reached the workspace, which changes my reading in 13.3.

**Q18. Configuration changes and database alerts, 60 days (Sentinel)**

```kql
AzureActivity
| where TimeGenerated > ago(60d)
| where ResourceId has_any ("sqldb-uat", "firewallPolicies", "azureFirewalls")
| where ActivityStatusValue in ("Success", "Succeeded")
| where OperationNameValue has_any ("write", "delete")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId
| order by TimeGenerated asc
```

```kql
SecurityAlert
| where TimeGenerated > ago(60d)
| where Entities has_any ("sqldb-uat", "10.30.2.14", "172.20.14.30", "45.83.220.61")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, Entities
```

*Expect:* when and by whom the rule or the database settings last changed, and any Defender alert on the database or host. 

**Q19. Read-only commands on the host (run by an administrator)**

```bash
# Output to a write-once location off the host. Hash before copying. No remediation in this step.
date -u; timedatectl 2>/dev/null; ls -l /etc/localtime
sha256sum /var/log/auth.log* /var/log/*sftp* 2>/dev/null
grep -h "finserve_settle" /var/log/auth.log* | sort
grep -h -E "Failed|Invalid user" /var/log/auth.log* | sort
last -Faiw | head -200; lastb -Faiw 2>/dev/null | head -200
getent passwd finserve_settle
sshd -T 2>/dev/null | grep -E "passwordauthentication|permitrootlogin|allowusers|chroot|forcecommand|subsystem|loglevel"
systemctl list-timers --all; ls -la /etc/cron* /var/spool/cron* 2>/dev/null; atq 2>/dev/null
ss -tanp; ps -eo pid,ppid,user,lstart,cmd --sort=lstart
find /opt/finrecon /settlement /tmp /var/tmp -xdev -type f -mtime -14 -ls 2>/dev/null
sha256sum /opt/finrecon/conf/deliver.cfg /opt/finrecon/conf/refresh_uat.ps1
```

*Expect:* the time zone and the clock (settles T6); every `finserve_settle` event and any failures; whether the account has a shell or is confined; scheduled jobs that could explain 04:11; recently changed files; hashes of the two config files. Do not print the two config files in a shared terminal. Output from a host the actor reached is not tamper-proof, so image first where possible.

## 30. Questions for FinServe (update to Section 11, through the mentor)

| # | Question | Why it matters |
|---|---|---|
| 12 | Does anyone at FinServe, Corebridge, Solvex or any supplier use 45.83.220.61? | Settles alternative N2 and the wording of the reply to Meridian. |
| 13 | What was actually done after the Inject 04 report on 14 October: sessions revoked, rule disabled, credential rotated, logs copied? | Decides whether the M365 session could have lasted all week and whether the credential changed. |
| 14 | Is SSH on `sftp-slo` meant to be reachable from the internet, and who owns the DC-SLO Fortigate policy? | Step P5. |
| 15 | How does the nightly UAT refresh run, and why does a refresh script sit on a DC-SLO host? | Alternative X2. |
| 16 | Does the host-local `finserve_settle` password match the Meridian one? A yes or no is enough. | If yes, one exposure is the other. |
| 17 | Who is FinServe's contact at Meridian for this, and what does the contract say about incident notice and delivery outside the window? | The reply to Meridian and Option B. |
| 18 | What did Marcus mean by "since February"? | Nothing I hold explains it. |
| 19 | Is auditing enabled on `sqldb-uat`, and where does it write? | Section 19 row 1. |
| 20 | Who takes the decision on tonight's settlement? | Section 22.3. |

> **Update (Inject 07):** questions 21 to 29 are in Section 32.12.

## 31. Contribution and AI Use

The team completes the bracketed fields. I have not named anyone and have not claimed that anyone did any work.

| Part | Drafted by | Reviewed by |
|---|---|---|
| Sections 1 to 11 (Inject 04) | [team member names from the Inject 04 pull request] | [ ] |
| Sections 12 to 14 (overview, evidence and assumptions, relationship) | [name] | [name] |
| Sections 15 to 17 (timeline, attack path, database access) | [name] | [name] |
| Sections 18 to 21 (evidence assessment, limitations, earliest compromise, severity) | [name] | [name] |
| Sections 22 and 23 (containment and recovery, evidence preservation) | [name] | [name] |
| Sections 24 and 25 (recommendations, references) | [name] | [name] |
| Sections 26 to 30 (changes to Sections 1 to 11, GRC handoff, gaps, queries, questions) | [name] | [name] |
| `INC-01-Evidence-Requests.md`, Sections 1 to 9 (Inject 06) | [name] | [name] |
| Section 32 (Inject 07 reassessment) and the notes marked "Update (Inject 07)" | [name] | [name] |
| `INC-01-Evidence-Requests.md`, Section 10 (Inject 07) | [name] | [name] |
| Pull request opened by | [name]. Rotate from the Inject 04 pull request. | other pair as reviewers |

Branches: `soc/<initials>/inc-01-escalation` (Inject 06) and `soc/<initials>/inc-01-impact` (Inject 07). One submission per inject for the team.

**AI use.** Claude (an AI assistant in a Claude Code session) was used to read the repository and the Inject 06 artefacts, build the evidence inventory, draft Sections 12 to 32 and the Evidence-Requests file (Inject 06 and Inject 07), and check the draft for internal consistency. It had no access to a tenant, a host or any FinServe system, and ran no query. [Team: edit this to say what you checked against the sources, what you changed, and what you rejected. Check every factual claim, in particular the dates, the time arithmetic and every quotation from an artefact.]

---

# Part 3. Inject 07 update: what the UAT database holds

## 32. Inject 07 — UAT Data Exposure Impact Reassessment

**Reassessed Wednesday 21 October 2026 (W3 D2), after I7-A1 arrived at 10:54 UTC (T13). This section extends this incident. It does not open a new one. Sections 1 to 31 stand as written, except where a note marked "Update (Inject 07)" says otherwise.**

| Item | Detail |
|---|---|
| Trigger | I7-A1, the Cloud Platform Lead's reply on what the nightly UAT refresh masks, and I7-A2, an extract of the refresh script |
| Previous rating | **Critical**, set Monday 19 October (W3 D1, Section 21). Before that, High (provisional) on 14 October (Section 6). |
| Revised rating | **Critical. Unchanged, and reconfirmed on 21 October on a changed basis** (32.6). |
| What changed | Not the tier. The ceiling on consequence, the number of people behind it, and the number of systems I cannot rule out (32.3, 32.4). |
| Status | **Provisional.** No tenant or host access, and no query run. Evidence Requests ER-21 to ER-32 (`INC-01-Evidence-Requests.md`, Section 10) are the route to closing it. |

**In four sentences.** The database that the 04:11 flows reached holds a copy of production in which only forenames, surnames and email addresses are masked, for 181,402 customers (I7-A1). The script the actor asked to open about eighteen minutes before the flows holds a database credential in plain text, used by the platform team for both production and UAT (I7-A2). Nothing shows that the credential was used or that any data was read, and nothing we hold could show it either way. The rating therefore stays Critical, and the list of things I cannot rule out is longer than it was on Monday.

### 32.1 New information

I7-A1 is a statement from the platform owner, not a query result. I7-A2 is an extract provided on request. Neither has been checked against a system (T14, T18). Document references (E1 to E12) are as in Sections 2 and 13.

| # | Fact | Source | Known before? | Effect on this incident |
|---|---|---|---|---|
| I7-N1 | The nightly refresh copies production into UAT, then masks forename, surname and email. Account numbers, sort codes, balances, full transaction history, dates of birth, addresses and National Insurance numbers come across as they are. | I7-A1; I7-A2 | **Partly.** E2 §3 recorded names and emails masked and account numbers, balances, transaction history and NI numbers unmasked. **New:** sort codes, dates of birth, addresses, and "everything else" (T17). | The unmasked set is complete enough to classify: D1 (date of birth, address, phone likely), D2 (NI number), D3 (account number, sort code, balance, transactions) (E4 §1). |
| I7-N2 | The UAT customer table holds 181,402 records. | I7-A1 | **No.** E4 §1 estimates about 180,000 subjects. | Gives the population behind the worst case (T18). |
| I7-N3 | The other fields are not masked because the UAT reconciliation test pack must match production figures. The decision was taken during Lighthouse on the reasoning that UAT sits behind the same network boundary as production. The script points to a decision record, PROD-TEST-042. | I7-A1; I7-A2 | **No.** E2 §3 gave the reason in outline only. | An accepted risk, not an oversight. Fixing it needs a plan for reconciliation testing (C-30). The boundary argument is contradicted by I6-A2 and I6-A3: an outside address logged in to a host inside the boundary, and that host reached UAT. |
| I7-N4 | `sqldb-uat` is in `sub-nonprod`. Defender for Cloud is on the Free tier, the landing-zone policy initiative is in audit-only mode, and 21 people hold Contributor. | I7-A1 | **Yes.** E2 §1, §4; Coverage-Gaps G7. | Confirms from the owner that UAT has no preventive control and no threat-detection plan. |
| I7-N5 | SQL auditing on `sqldb-uat` is on, "I believe", and "not connected to anything". | I7-A1 | **No.** E7 does not record UAT auditing; Coverage-Gaps Q7 asked. | A belief, not a configuration. Auditing with no destination records nothing, so the state is still **Unknown which** (32.5). |
| I7-N6 | The refresh script holds, in plain text, one service account and one password used by both the production connection and the UAT connection. It copies with overwrite, then masks. | I7-A2 | **No.** I6-A2 listed the file. Section 15 recorded "purpose and contents **[U]**". | **The file the actor asked to open is a credential store with reach into production.** This is the largest change (32.2, 32.3). |
| I7-N7 | The script header says it runs at 02:00 by scheduled task, and the extract is "held on the DC-SLO host". It does not say which host runs the task. | I7-A2 | **Conflicts** with E4 F10 and E1 §3.1, which place the refresh within Azure, reaching `sqlmi-prod` from the UAT App Service (CHG-2024-0881). | Changes explanation X2 (32.2). A route from DC-SLO to production SQL may be intended and is not documented (T16). |

I do not reproduce the credential, the account name or any connection detail here. The finding is: **a service-account password hardcoded in a scheduled script, shared between the production and UAT connections.**

**Findings from Inject 07**

| ID | Finding | Evidence |
|---|---|---|
| F7-1 | A static, plain-text database credential shared by the production and UAT connections sits in a script in a directory the SFTP account could list. | I7-A2; I6-A2 |
| F7-2 | UAT holds production personal and financial data for 181,402 customers with three fields masked. | I7-A1; I7-A2 |
| F7-3 | UAT has no working detection or prevention: Free-tier Defender, audit-only policy, SQL auditing unconfirmed and uncollected. | I7-A1; E2 §1; E7 §1 |
| F7-4 | A network path from the legacy host to UAT SQL exists, under a rule whose documented purpose is different. A standing exception (CHG-2024-0881) also lets the UAT App Service reach production SQL, with no expiry, and no analytics rule watches permitted flows between the zones. | I6-A3; E1 §3.1; E8; engagement plan, joint touchpoint 2 |
| F7-5 | 21 permanent Contributors can administer UAT without a database login. | I7-A1; E2 §4; E9 (INC-2025-0924-002, a Contributor grant outside a change, approved retrospectively) |
| F7-6 | The nightly overwrite and the 7-day restore window destroy UAT-side evidence quickly. | I7-A2; E2 §3 |
| F7-7 | The documents and the script disagree on where the refresh runs. | I7-A2 against E4 F10 and E1 §3.1 |

**Why masking names and email addresses does not de-identify this database**

- **What was masked.** Three fields. The replacement values are built from the customer ID (I7-A2), so the customer ID survives and links every row back to production.
- **What was left identifies people without a name.** A National Insurance number is issued for life and identifies one person. A date of birth with an address, or a sort code with an account number, singles a person out. UK GDPR treats data as personal if a person can be identified directly or indirectly by means reasonably likely to be used (Article 4(1), Recital 26). At best this is pseudonymised data. It is not anonymised. For the SOC, a breach of this database is a breach of customer data, not of "test data".
- **The masking is not durable.** The script copies first and masks afterwards, in a separate statement (I7-A2). For some interval each night the UAT database holds unmasked names and emails, and any restore point inside that interval holds them too. The order is **[F]**. The interval's length is **[U]** (CR11).
- **Only one table is masked.** The statement updates the customer table. Payee and counterparty names in transaction records are not touched. Whether such fields exist is **[U]** (schema not seen), so I rate "other data subjects are in the set" **[A, low]** (CR10).

GRC owns the conclusions on lawful basis and the DPIA. The SOC states only the factual consequence.

### 32.2 Relationship to the existing incident

**Sequence on Sunday 18 October (UTC).** Section 15 is not changed. This table adds the one documented scheduled event and I7-A1.

| Time (UTC) | Event | Source | Basis |
|---|---|---|---|
| 02:00 | Documented start of the nightly refresh. Whether it ran, on which host, and when it finished are not shown. If the host schedules in local time, 02:00 is 01:00 UTC (T6, T16). | I7-A2 header | **[F]** that the header says so. Occurrence **[U]**. |
| 03:51:44 | Password login as `finserve_settle` from 45.83.220.61. | I6-A2 | **[F]** (T6, T9) |
| 03:52:02 | Directory listing of `/opt/finrecon/conf`. | I6-A2 | **[F]** |
| 03:52:40 | Open-for-read request: `deliver.cfg`. | I6-A2 | **[F]** request |
| 03:53:18 | Open-for-read request: `refresh_uat.ps1`, 38 seconds later. | I6-A2 | **[F]** request. Content **[A]** (T14). |
| 04:02:55 | Disconnect. | I6-A2 | **[F]** |
| 04:11:09 | Allow, 172.20.14.30 to 10.30.2.14:1433. 17 m 51 s after the `refresh_uat.ps1` request, 8 m 14 s after disconnect. | I6-A3 | **[F]** |
| 04:11:12 | Second Allow. | I6-A3 | **[F]** |
| 04:14:38 | Third Allow, 3 m 29 s after the first. | I6-A3 | **[F]** |
| Wed 21 Oct, 10:54 | I7-A1 arrives, 3 d 6 h 42 m 51 s after the first flow. | I7-A1 | **[F]** (T13) |

If the host clock is British Summer Time (T6), the reads were at 02:53 UTC and the gap to the first flow is 1 h 17 m 51 s, not 17 m 51 s. The order survives. The proximity does not.

**The five events and what links them**

| Link | Event | Direct evidence | What is inferred | Basis |
|---|---|---|---|---|
| A | Unauthorised SFTP access | Password logins from 45.83.220.61 (I6-A2); Meridian names the same address (I6-A1). | "Unauthorised": nobody has claimed the address (ER-16). | **[F]** logins. **[A]** unauthorised. |
| B | The script was read | An open-for-read request at 03:53:18. No `close` line or byte count (T15). | That the request was served and the content reached the actor. | **[F]** request. **[A, moderate]** read. |
| C | The shared credential was in what was read | The extract holds it (I7-A2). | That the extract is the file on the host at 03:53:18, and that the credential was valid then (T14). | **[F]** extract. **[A]** same file, valid. |
| D | A connection to UAT | Three Allow flows (I6-A3). | Who or what started them (below). | **[F]** flows. **[U]** initiator. |
| E | Sensitive data in UAT | I7-A1; I7-A2; E2 §3 | That it was the same on 18 October as today (T18). | **[F]** design. **[A]** on the date. |

**Assessment**

| Question | Assessment | Confidence |
|---|---|---|
| Are A to E one incident? | Yes. One record, as in Section 14. | **High** (unchanged) |
| Did the actor receive the credential by reading the script? | Likely, if the request was served and the file on the host holds what I7-A2 shows. | **Moderate** **[A]** |
| Did the actor use the credential, at 04:11 or at any time? | **Not established.** Possible. | **Not rated.** Open. |

**A read is knowledge. A use is an act.** The log shows a request to open a file. The firewall shows a network permit. Between them sit four things nobody has evidenced: the content arriving, the credential being valid, a login, and a statement. The timing (17 m 51 s) and the mechanism (a credential in the file) make the link plausible. They do not make it proven. Plausible is the standard for acting (rotate, restrict). It is not the standard for saying what happened.

**The 04:11 connection: explanations, updated.** X1 to X4 are from Section 17.4. X5 and X6 are new. I still do not rank them.

| # | Explanation | What Inject 07 changes | What separates it |
|---|---|---|---|
| X1 | The actor, by a shell, a second session or a planted job, on the host. | The mechanism now exists: a credential read 18 minutes earlier. Still no evidence of code execution on the host. | Whether the `finserve_settle` account has a shell; client tools on the host; sessions and processes at 04:11 (ER-23). |
| X2 | The refresh job, or a related routine job, on this host. | **Stronger on path, unchanged on timing.** The script connects to UAT a second time after the copy, to mask. A copy that runs for two hours would put those connections at about 04:10, not at 02:00. The flows are three connections in 3.5 minutes, which fits "copy ends, mask runs, check". Against: the task's host is not stated (T16), and E4 and E1 place the job within Azure. | The baseline: do three similar flows from 172.20.14.30 appear on earlier nights, at what hour (Q12, Q20)? Run history of the task (ER-22). Query Store in a restore at 05:15 (ER-21). |
| X3 | A persistence job the actor planted earlier. | Unchanged. No write operations are shown. | Write operations in the full sftp log; timers and cron (ER-23). |
| X4 | A different party using the host. | Unchanged. | Full `auth.log` (ER-23). |
| X5 | **New.** The UAT reconciliation test pack, run from this host. | I7-A1 says the test pack reconciles UAT against production figures. The script sits under the FinRecon directory. Nothing says where the pack runs. | Where and when the pack runs (ER-22(c)); the baseline. |
| X6 | **New.** The actor tunnelled to UAT through the host over SSH, in a session open at 04:11. | Needs no code on the host. The firewall would show the host as the source. The 03:51:44 session had closed, so a different session would have to be open. None is shown, and nine are unseen. | Any `sshd` session open from 04:11:09 to 04:14:38 in the full `auth.log`; forwarding settings in `sshd` (Q19 additions). |

**Three tests would separate them, and each uses data FinServe may already hold.**

1. **Baseline (ER-25).** Similar flows on earlier nights at a consistent hour make the job the leading explanation for the flows. They say nothing about whether the credential was also read by someone else. No earlier flows from this host make X2 and X5 much weaker.
2. **A session at 04:11 (ER-23).** An open `sshd` session at 04:11 supports X6 or X1. None, with no timer or process, points to X2 or X5.
3. **Records of the credential's use with a client address (ER-24, ER-26).** A login from 45.83.220.61, or from the host outside the job's pattern, is the first direct evidence of use.

### 32.3 Revised worst-case impact

**The worst case for the connections at Sunday 18 October 04:11:09 to 04:14:38 UTC (W2 D7).** This is a ceiling, not a finding. Nothing here is claimed to have happened.

> A person holding the refresh account's credential, read from `refresh_uat.ps1` at 03:53:18, logged in to `sqldb-uat` through the host, read the customer, account and transaction tables for all 181,402 customers, and moved the result out of the estate through the SFTP service, an SSH tunnel or an export. They then used the same credential against `sqlmi-prod` to collect what UAT masks (names, email addresses), and left a database user or job for later access.

**What the connection could have reached, if a login occurred**

| Data in UAT (I7-A1) | Category (E4 §1) | Reachable | What an unauthorised holder could do with it |
|---|---|---|---|
| Account numbers, sort codes | D3 Financial, Restricted | Yes | Identify each customer's account exactly. Impersonate the bank or a payee in calls and messages. |
| Balances | D3 | Yes, as at the latest refresh | Pick high-balance customers. Make impersonation credible. |
| Full transaction history | D3 | Yes | Learn employers, payees and regular payments. Build convincing scam scripts. Counterparty names and references may sit in free text **[A, low]** (CR10). |
| Dates of birth, addresses | D1 Identity, Confidential | Yes | Pass identity checks at other firms. Identity fraud. Targeted post and phishing. |
| National Insurance numbers | D2, Restricted | Yes | Identity, credit and benefit fraud. The number is issued for life, so the harm does not expire. |
| Forenames, surnames, email addresses | D1 | **No, not as names or emails.** Replaced with values built from the customer ID. | Not usable directly. The customer ID links each row to production. |
| Phone numbers and other columns | D1 (phone), possibly D5 | Likely (T17) | Contact customers directly with all of the above. |

**What the worst case adds since Inject 06**

| Dimension | Worst case in Sections 17.4 and 21.2 | Worst case now |
|---|---|---|
| Mechanism | A connection read data. No account of how the actor would log in. | A credential read 18 minutes earlier. Mechanism documented, use not shown. |
| Systems | `sqldb-uat` | `sqldb-uat`, and `sqlmi-prod` if the same credential is valid and reachable. **Not evidenced.** |
| People | "Restricted customer data", about 180,000 subjects (E4 §1) | 181,402 customer records (I7-A1), and possibly payees named in transactions |
| Data | D2 and D3 (E2 §3) | D1, D2 and D3, with a join key to production; names and emails if production was reached |
| Harm | Confidentiality | Confidentiality; integrity of UAT (the job overwrites it); persistence in a database if the account's rights allow |
| Visibility that would have helped | None | None, and now confirmed by the owner (I7-N4, I7-N5) |
| Time the credential has been exposed | Not considered | The script header is dated 11 March 2024, 31 months before 18 October. That date is a comment in the file, not file metadata. The credential may be older or newer than the header. |

**Beyond UAT.** I7-A2 defines a production connection and a UAT connection with the same account and password. A full-database copy needs read access to the whole production database, so I treat the account as a production credential **[A]**. Its rights are not documented (ER-22). A route from the host to production SQL is not in the documents. The documented route into production SQL from non-production is CHG-2024-0881: the UAT App Service may reach `sqlmi-prod` on port 1433 for the nightly refresh, with no expiry date (E1 §3.1). Anyone who can run code in that source range, for example a Contributor on `sub-nonprod` (T19), could try that route, and a valid production credential is the one thing they would still need. The script's shared credential is such a credential **[A]**. The flows supplied reach UAT only. So the exposure of the credential is a production-side finding in its own right. **Any use against production, by either route, is not evidenced and is not claimed.** The production half is where retained evidence is best: `sqlmi-prod` auditing is on, with a one-year immutable copy in storage, outside Sentinel (E7 §3).

**Consequences if the worst case were real**

| For | Consequence |
|---|---|
| Customers | Impersonation of the bank and of customers using real account details, balances and transactions. Identity, credit and benefit fraud using NI numbers, with no practical reset. Targeted phishing and calls. Distress and time spent protecting accounts. |
| FinServe | A personal data breach affecting about 180,000 people, including Restricted categories, for the DPO to assess for UK GDPR notification to the ICO and communication to customers. Questions for the FCA and PRA that GRC and the CISO decide. Fraud losses and reimbursement. Remediation costs. Loss of confidence. |
| Partners | Meridian Trust and Corebridge may have their own notice duties. SOC has not seen the contracts. |

These are the matters GRC and the DPO assess. The SOC names them so the worst case is complete, and does not decide any of them.

**Not claimed:** that the credential was obtained, that any login happened, that any data was read, altered or removed, that production was reached, or that any customer was harmed.

### 32.4 Evidence assessment

Basis tags and confidence words are as defined at the top of this report. IDs are used in the rest of Section 32.

#### 32.4.1 Proven

| ID | Statement | Source | Limit |
|---|---|---|---|
| I7-P1 | Password logins as `finserve_settle` from 45.83.220.61 to `sftp-slo` at Sat 17 Oct 22:04:11 and Sun 18 Oct 03:51:44. | I6-A2 | A hand-retrieved extract, two sessions of eleven, no hash (13.3). Host time zone assumed (T6). |
| I7-P2 | In the second session, open-for-read **requests** for `deliver.cfg` (03:52:40) and `refresh_uat.ps1` (03:53:18) in `/opt/finrecon/conf`. | I6-A2 | Requests only (T15). |
| I7-P3 | Three Allow records from 172.20.14.30 to 10.30.2.14:1433 at 04:11:09, 04:11:12 and 04:14:38, under rule `CHG-2025-0132-dev-fileshare`. | I6-A3 | Platform log. Three rows, no baseline, query window not stated. A rule match, not a login (T19). |
| I7-P4 | The extract of the script holds a plain-text service-account password used by both the production and UAT connections. It copies with overwrite and then masks forename, surname and email. | I7-A2 | An extract. Not hashed. Not shown to be the file on the host (T14). |
| I7-P5 | The nightly refresh masks only forename, surname and email. Everything else comes across as in production. | I7-A1; I7-A2; E2 §3 | A statement of design by the platform owner. Not a query result. |
| I7-P6 | The UAT customer table holds 181,402 records. | I7-A1 | A statement. Count at about 21 Oct, not 18 Oct (T18). |
| I7-P7 | `sub-nonprod`: Defender for Cloud Free tier, policy initiative audit-only, 21 permanent Contributors. | I7-A1; E2 §1, §4 | Statement and document. Group membership not listed. |
| I7-P8 | No SQL audit data from `sqldb-uat` reaches Sentinel. | I6-A3; E7 §1 | Says nothing about audit data elsewhere. |
| I7-P9 | `sqlmi-prod` auditing is on, written to storage with a one-year immutable policy, with no Sentinel connector. | E7 §3 | Document. Action groups unknown (Coverage-Gaps Q7). |
| I7-P10 | Documented retention: host logs 30 days; Sentinel 60 days; Entra raw sign-ins 30 days; `sqldb-uat` point-in-time restore 7 days. | E7 §3, §4; E2 §3 | Documents, not tests. |

#### 32.4.2 Assessed as likely

| ID | Statement | Reasoning | Confidence |
|---|---|---|---|
| I7-L1 | The file requested at 03:53:18 is the script in I7-A2 and carries the same credential. | Same name and directory family; the platform team supplied the extract from the DC-SLO host; the header says the file is old. Not hashed (T14). | Moderate to high |
| I7-L2 | The request at 03:53:18 was served and the content reached the actor. | The actor went to the directory and named the file; no failure line is shown; the session continued for nine more minutes. No byte count (T15). | Moderate |
| I7-L3 | The credential was valid at 03:53:18. | The nightly job needs it, and the job is said to run nightly. Nobody has said it was changed. | Moderate |
| I7-L4 | UAT held the data listed in I7-P5 on 18 October for about the same population as today. | The refresh is nightly (E2 §3; I7-A1). Whether the 02:00 run on 18 October completed is **[U]**. | High |
| I7-L5 | Masking names and email does not de-identify the database. | 32.1. | High |
| I7-L6 | The rule `CHG-2025-0132-dev-fileshare` is broader than its documented purpose. | It matched DC-SLO traffic to UAT SQL. E1 §3.1 documents it as Dev subnet to a shared-services file server. | Moderate |
| I7-L7 | The 04:11 flows are not the 02:00 start of the scheduled job. | 2 h 11 m 09 s later. But post-copy connections follow the end of the copy, not the start (X2). | Moderate. It does not separate routine from hostile. |
| I7-L8 | The operator of the SFTP and M365 activity is the same. | Unchanged from Section 14. | Moderate to high |

#### 32.4.3 Cannot rule out

| ID | What cannot be ruled out | Why | Class (Section 19) | What would settle it |
|---|---|---|---|---|
| I7-C1 | The actor received the file contents. | No `close` line or byte count; hand-retrieved extract. | Not supplied. Not enabled if the log does not record closes. | ER-23 |
| I7-C2 | The actor logged in to `sqldb-uat` with the credential, at 04:11 or at any other time, including during the nine unseen host sessions. | A flow is not a login. No audit source we hold. UAT auditing is a belief (I7-N5). | **Unknown which:** Not enabled, Not forwarded or Not supplied. | ER-26, ER-29, ER-21 |
| I7-C3 | Statements were run and data was read, up to all 181,402 customer records and the linked account and transaction tables. | Same. Query Store inside a restore is the only UAT-side lead. | As C2, and Aged out after Sun 25 Oct 04:11. | ER-21 |
| I7-C4 | Data in UAT was written, altered or deleted, or users, roles or objects were created. | The account can overwrite the database (I7-A2). The overwrite at 02:00 on 19, 20 and 21 October replaced UAT-side state. | Aged out (overwritten), unless restored. | ER-21 |
| I7-C5 | The credential was used against `sqlmi-prod`: from the host, from the UAT App Service under CHG-2024-0881, from another internal address, or from the internet if a public endpoint is enabled. | No production-bound flows or audit rows supplied. The CHG-2024-0881 flows are logged but no rule watches them (E8). Azure Firewall would not see a direct public-endpoint connection. Audit action groups unknown. | Not supplied. Not forwarded. | ER-24 |
| I7-C6 | Data left the estate: through the SFTP service in an unseen session, an SSH tunnel, a direct database connection, or a control-plane export to storage. | Fortigate traffic logs not shown to arrive (Section 19, row 4). Blob logs never existed (row 3). Nine sessions unseen (row 10). | Never existed (blob). Not forwarded. Not supplied. | ER-23, ER-25, ER-32 |
| I7-C7 | The credential was exposed before 17 October, to anyone who could read the directory (staff, FinRecon support, a backup restore), and has been used by someone else. | Plain text in a script with a header dated 11 March 2024. Readable by an unconfined SFTP account. Copies in backups (90 days) and wherever the script was copied. | Aged out for the host and UAT horizons. Not supplied for the one-year production audit. | ER-22, ER-24 |
| I7-C8 | Other consumers of the same credential exist (scripts, hosts, pipelines) and are exposed. | "Shared" means used in more than one place. No inventory. | Not supplied | ER-22(c) |
| I7-C9 | Someone with Contributor on `sub-nonprod` has read, exported or copied UAT data. | Control-plane actions need no database login. A context fact, not attributed to this incident. | Not supplied (Activity Log). Never existed (data plane). | ER-30, ER-31, ER-32 |
| I7-C10 | Other data subjects (payees and counterparties in transaction records) are in the exposed set. | Only the customer table is masked. Schema not seen. | Not supplied | ER-29(c) |
| I7-C11 | UAT restore points or backups hold unmasked names and emails. | The script masks after the copy, so restore points inside that interval hold them. The interval is not known. | Not supplied | ER-22(b), ER-21 |

**Has "Cannot Rule Out" expanded since Inject 06? Yes.** Inject 06 (Section 19, 15 rows) asked what the 04:11 connection did and how the actor got in. Inject 07 adds:

1. **A mechanism.** "What did the connection do?" is now "did a specific, plausible, high-capability act happen?" (C2, C3).
2. **A system.** `sqlmi-prod` enters the blast radius through a shared credential (C5).
3. **Integrity and persistence at the database layer** (C4).
4. **A longer exposure window** for the credential, up to 31 months and not bounded below (C7), and **other consumers** (C8).
5. **New routes for data to leave**: a control-plane export, a public endpoint, a tunnel (C6, C9).
6. **A defined population**, 181,402 customers, and possibly people who are not customers (C10, C11).
7. **A softer fact.** UAT auditing is a belief, which widens "Unknown which" in Section 19, row 1 (I7-N5).

Nothing arrived that excludes an earlier item. One item shrank: the contents of `refresh_uat.ps1`, **[U]** in Section 19, row 9, are now known from an extract (T14).

### 32.5 Data access and exfiltration assessment

| Question | Answer | Why |
|---|---|---|
| Can database access be confirmed? | **No.** | The only evidence is that the network permitted three connections. No login, session or statement is evidenced anywhere we hold. |
| Can specific SQL operations be identified? | **No.** | No source of statements exists in Sentinel for `sqldb-uat`. Whether one exists elsewhere is unknown (I7-N5). The single lead is Query Store in a restored copy (ER-21). |
| Can data extraction be confirmed? | **No.** | Nothing shows rows returned, bytes moved or a file created. |
| Can exfiltration be excluded? | **No.** | Routes exist that we cannot see: unseen sessions, a tunnel, a direct connection, an export (C6). Excluding exfiltration needs complete host, network, database and storage evidence. We have none of the four. |
| What evidence is missing? | See the table below. | |

**The exposure ladder.** Each rung needs evidence of its own. A rung is not proven because the one above it is.

| Rung | Statement | Status | Evidence, or why not |
|---|---|---|---|
| 1 | The actor logged in to the host. | **Proven** (limits in 13.3) | I7-P1 |
| 2 | The actor asked to open the script. | **Proven** | I7-P2 |
| 3 | The request was served and the content reached the actor. | **Assessed, moderate** | I7-L2. No byte count. |
| 4 | The file held the credential shown in I7-A2. | **Assessed, moderate to high** | I7-L1 |
| 5 | The credential was valid. | **Assessed, moderate** | I7-L3 |
| 6 | The actor used the credential. | **Not established** | Nothing shows it. |
| 7 | A login to `sqldb-uat` succeeded. | **Not established** | A flow is not a login. |
| 8 | Statements read customer data. | **Not established** | No statement source. |
| 9 | Data left `sqldb-uat` into the actor's control. | **Not established** | Nothing. |
| 10 | Data left the estate. | **Not established** | Routes not visible (C6). |
| P | The credential was used against `sqlmi-prod`. | **Not established** | No production-bound flows or audit rows supplied. |

**A firewall connection is not database activity.** A database connection has layers, and the firewall sees one of them.

1. A connection attempt matches a rule. **The firewall logged this.**
2. The connection completes. The log does not say.
3. The client and server negotiate (the job is configured for encrypted connections, so a capture would not show statements).
4. A login is accepted or refused. Only the database knows.
5. Statements run and rows return. Only the database knows.
6. Data leaves. Only host, network or storage logs know.

A network-rule row records that a flow matched a rule. It does not record login, statements, bytes or duration (T19). The three rows are layer 1 of that list and nothing more.

**Why missing SQL audit records do not show that no access occurred.** Evidence is informative only if, had the event happened, the source would have shown it. Ask that of the empty query. Had someone read every row of `sqldb-uat` on 18 October, would `SQLSecurityAuditEvents` in `law-sentinel-prod` have held a record? Not unless the database writes audit events to that workspace, and E7 §1 says it does not. So the empty result would have looked the same whether the database was read or not. It has no value in either direction. There are four reasons the result could be empty, and they have different fixes:

1. Auditing is enabled and writes to a destination Sentinel does not read (storage, another workspace). Records exist. **Not forwarded.** Recoverable.
2. Auditing is enabled with no destination, or never was. No record was ever created. **Never existed / Not enabled.** Not recoverable.
3. Auditing wrote records and retention removed them. **Aged out.**
4. The workspace table is absent or ingestion failed (13.3). **Not forwarded.**

ER-26 and ER-28 tell us which. Until they do, the answer is **Unknown which**.

**What is missing, by question**

| To answer | Missing | Request |
|---|---|---|
| Did the actor receive the file? | `close` lines and byte counts | ER-23 |
| Was there a login, and as whom? | UAT audit, or connection telemetry; production audit for the same account | ER-26, ER-29, ER-24 |
| What ran? | Query Store in a restore; audit statements | ER-21, ER-26 |
| Was it routine? | Baseline flows and job run history | ER-25, ER-22 |
| Could a session have carried it? | Sessions open at 04:11; forwarding settings | ER-23 |
| Did data leave? | Fortigate traffic logs, storage activity, control-plane exports | ER-32, ER-30 |

### 32.6 Severity reassessment

| Item | Entry |
|---|---|
| Previous severity rating | **Critical** (19 October, W3 D1, Section 21.2). Before: High, provisional (14 October, Section 6). |
| Revised severity rating | **Critical.** No change. |
| Date of reassessment | **Wednesday 21 October 2026** (W3 D2), on receipt of I7-A1 at 10:54 UTC |
| Reason | The tier does not change. Its basis does (below). |
| Impact of the newly identified data categories | D2 (NI numbers) and D3 (account, sort code, balance, transactions), both Restricted; D1 (date of birth, address, likely phone), Confidential; each with a join key to production. A plain-text credential with reach into production, which is a D7-type secret. D4 is not in scope (PANs are not stored, E4 §1). D5 is possible and unconfirmed. |
| Customer records potentially exposed | **181,402** in `sqldb-uat` (I7-A1, T18). Production holds the same population with names and emails unmasked (about 180,000 subjects, E4 §1). Account and transaction counts were not supplied (E4 §1: about 215,000 accounts in production). |
| Confidence | **Rating: high.** **That data was accessed: not assessable.** The evidence cannot separate access from no access. |
| Remaining uncertainty | I7-C1 to I7-C11. In order of weight: whether the credential was used (C2, C5), whether anything left (C6), how long it was exposed (C7), who else holds it (C8). |

**How the framework was applied.** The project has no formal incident scale. Section 6 sets the method: tiers defined by named triggers, with what would raise or lower each. FinServe's own scale has not been supplied (Section 11, question 6, still open), and I have not invented one. Coverage-Gaps §3 supplies three factors, which I apply as they are: what is exposed (Restricted data of about 180,000 subjects), what the attacker could achieve unobserved (fraud, identity theft, persistence), and what compensating visibility exists (none on UAT). That method defines Critical as high impact and high consequence with little or no compensating visibility. This incident meets all three parts.

**Why the rating stays Critical.** Three reasons, each enough on its own while it stays open:

1. A credential for production and UAT databases, in plain text, was requested by an unauthorised actor and is assessed as likely to have been received. It has not been rotated, as far as I know (ER-16).
2. The data at risk is Restricted and covers about 180,000 people, with no way of seeing what was done to it.
3. Use cannot be ruled out, and for UAT-side evidence the time to find out runs out on Sunday 25 October.

**What is not driving the rating.** That the 04:11 flows were hostile. That is unresolved (X1 to X6). If they were the refresh job, the rating would stand on reasons 1 to 3.

**Why not higher.** Critical is the top tier in the method in use. The new facts raise the ceiling on consequence and the evidence behind the tier. They do not create a tier above it. If FinServe's scale has a tier for a confirmed data breach, a confirmed read of UAT or production customer data would move the incident there.

**Revised conditions for High.** These replace the lowering conditions in Section 21.2, which could no longer be met as written: the actor's reads already went beyond settlement files. All of the following are needed:

1. The credential is rotated on both sides, after its metadata is captured (C-17).
2. The `sqlmi-prod` audit shows no use of the account except by the platform job's known source and times, over the credential's life or the retained year (ER-24).
3. Either the 04:11 pattern is in the nightly baseline (ER-25), or a restore of UAT shows no read of customer tables in the window (ER-21).
4. The full host log shows no sessions beyond the eleven and no writes (ER-23), and Meridian's logs show nothing beyond FinServe's own deliveries (ER-13).

It would not go lower than High until the host is rebuilt and every secret in `/opt/finrecon/conf` is rotated.

**Priority inside the incident.** Everything above is Critical at the incident level. The work is ordered by what is lost soonest and what buys most.

| Rank | Item | Why this rank | Action |
|---|---|---|---|
| 1 | Credential exposure (F7-1) | Certain action, high value, low cost. Rotation destroys one piece of evidence, so capture comes first. | C-17, C-18 |
| 2 | Was production reached? (I7-C5) | Largest blast radius. Answerable from a retained, immutable source. | C-20 |
| 3 | UAT-side evidence expiring (F7-6) | Hard limit Sun 25 Oct 04:11. Then it is gone. | C-19 |
| 4 | Was UAT read? (I7-C2, C3) | Decides the data-protection outcome. Mostly unanswerable except through 3 and the audit configuration. | C-19, C-21 |
| 5 | Paths and controls (F7-3 to F7-5) | Conditions that let this happen. Fix this week. | C-22 to C-27 |
| 6 | Process redesign (F7-2, F7-7) | Removes the root cause. Weeks. | C-28 to C-33 |

**Severity history**

| Date | Rating | Section | Trigger |
|---|---|---|---|
| Wed 14 Oct | High, provisional | 6 | Account takeover, files removed, scope open |
| Mon 19 Oct | Critical | 20 | Unfamiliar login on the SFTP host (trigger named in Section 6) |
| Wed 21 Oct | Critical, reconfirmed | 32.6 | I7-A1 and I7-A2: basis changed, tier unchanged |

### 32.7 Scope reassessment

| Component | Scope after Inject 06 | Scope now | Evidence | Not claimed |
|---|---|---|---|---|
| DC-SLO SFTP host (`sftp-slo`) | Accessed by an unauthorised actor; a pivot candidate | **Also a credential store.** It holds a script with a shared database credential. A pivot to UAT is now a mechanism, not a guess. | I6-A2; I7-A2 | Code execution on the host |
| `finserve_settle` | Exposed; suspended by Meridian | Unchanged. The account could list `/opt/finrecon/conf`, so it was not confined. | I6-A2 | That the host and Meridian passwords match (T7) |
| `sqldb-uat` | A permitted network flow | **A potentially accessed store of production-grade data** for 181,402 customers | I6-A3; I7-A1 | A login, a query, a read |
| The shared refresh credential | Not in scope | **In scope as exposed.** Assessed likely to have been received. | I7-A2; I7-L2 | Use |
| `sqlmi-prod` | Not in scope | **In scope as a credential exposure and a possible target.** Reachable from non-production through CHG-2024-0881. | I7-A2; E7 §3; E1 §3.1 | **Production database compromise.** No production-bound flow, login or query is evidenced. |
| Customer data | Possible | **Potentially exposed: 181,402 records** (the ceiling) | I7-A1 | Any access, extraction or loss |
| Other consumers of the credential | Not in scope | Unknown (C8) | None | Anything |
| Other DC-SLO workloads | Unknown | Unchanged | | |
| M365, Rachel Oduya | Compromised session | Unchanged | Sections 3 to 5 | |
| The 21 Contributors | Not in scope | **A context fact, not an incident finding.** Their access is a way into UAT that needs no credential (C9). | I7-A1; E2 §4 | That any of them acted |

**Boundary.** I have widened the scope to the credential and to the two databases it opens, as exposures. I have not widened it to production as compromised, to the Contributors as actors, or to any other host.

### 32.8 Recommendations

Each action says which finding it addresses and how. Numbering continues the plan in Section 22.2 (C-01 to C-16). C-08 (item 3), C-09, C-10 and C-14 are sharpened or replaced here.

#### Immediate

| ID | Action | Finding and how it helps | Owner | Timing and caution |
|---|---|---|---|---|
| **P1** C-17 | **Capture, then rotate.** Record the refresh account's creation, modification and password-last-set times, roles and permissions on `sqlmi-prod` and the UAT server (Q24). Then retire the old credential, production side first, and issue two different replacements, one per side, held in Key Vault and not in a script. | **F7-1.** Ends the use of anything the actor read. Capturing first keeps the one date that bounds the exposure, which rotation overwrites (T19). | Adeola Balogun, with a DBA (to be confirmed); SOC present | Capture first. Rotate the same day, after the host evidence in C-03. The 02:00 job will fail until C-18 is done. |
| **P1** C-18 | **Suspend the nightly refresh.** Disable, do not delete, the scheduled task wherever it is found (ER-22). | **F7-6, F7-7.** Stops tonight's overwrite of UAT and stops a noisy failure on the rotated credential. Costs a day of UAT currency. | Adeola Balogun | **Before 02:00 on Thu 22 Oct** (15 hours after I7-A1) |
| **P1** C-19 | **Secure UAT restore points.** Restore `sqldb-uat` into an isolated, access-limited database at Sun 18 Oct 03:45, 04:20 and 05:15 UTC. The last lets the 04:00 to 05:00 Query Store interval persist (T19). A DBA reads Query Store and the user, role and object lists. Replaces C-10. | **F7-6.** The only route to any UAT-side statement evidence. | DBA or cloud platform (to be confirmed) | **Hard limit Sun 25 Oct 04:11.** Treat every restore as production data. First confirm that the nightly overwrite has left these restore points. |
| **P1** C-20 | **Read the production audit** for the refresh account and for any login from 172.20.14.30 or 45.83.220.61 (ER-24, Q23). | **I7-C5, F7-1.** Decides whether the production half was used. | DBA with storage access; Marcus Ifill | Within 24 hours. Read in place. |
| **P1** C-21 | **Investigate the SFTP-to-UAT connection.** Run the baseline (Q12, Q20, Q21), check the full `auth.log` for a session at 04:11, and read `sshd` forwarding settings and client tools (Q19 additions). Write a one-page call: routine, hostile or still open, with the evidence. | **Section 32.2, X1 to X6.** Turns an open question into a ruling, or says exactly why it cannot be ruled. | SOC with Marcus Ifill; Infrastructure | 24 to 48 hours |
| **P1** C-22 | **Restrict access paths.** (a) After C-18, apply the deny in C-09. (b) Export, then disable public network access on the UAT server and remove rules not needed. (c) Check whether the `sqlmi-prod` public endpoint is enabled and what the NSG allows. (d) Keep the script and any secrets out of the SFTP account's reach on any rebuilt host. (e) Confirm the source range of CHG-2024-0881 and that the refresh really uses it, then give the exception an expiry. | **F7-4, I7-C5, I7-C6.** Closes the routes a holder of the credential could use without the host. | Cloud platform; network (to be confirmed) | Today and 48 hours. Export each setting first (ER-29, ER-24). |
| **P1** C-23 | **Escalate in writing to the CISO today and send GRC the Section 32.9 package today**, not tomorrow. DPO told if the CISO agrees. | **F7-2.** Inject 01 makes anything likely to need ICO, FCA or PRA notification a same-day trigger. The DPO's decisions depend on facts held now. | SOC team | Today |

#### Short-term (this week)

| ID | Action | Finding and how it helps | Owner | Timing and caution |
|---|---|---|---|---|
| **P2** C-24 | **Collect SQL audit centrally.** Enable auditing on the UAT server and confirm it on `sqlmi-prod`, with authentication and batch-completed action groups, to `law-sentinel-prod` and an immutable storage account. Connect the connector. Replaces C-14. | **F7-3.** Makes Section 19 rows 1 and 2 answerable for the next event. No effect on 18 October. | Marcus Ifill; cloud platform | W3 D3 to D5 |
| **P2** C-25 | **Turn on Storage diagnostics** for every storage account in `sub-nonprod` and any account used for SQL audit or export, then `stfinservedocs` (G2). | **I7-C6.** Gives blob access logs for the export route. No effect on 18 October. | Cloud platform | W3 D3 to D5 |
| **P2** C-26 | **Review Contributor on `sub-nonprod`.** List the members behind the 21, remove standing access not needed this week, use PIM (licensed, not configured, E2 §4) for the rest. Alert on role grants and on changes to SQL auditing, firewall or administrator settings (DET-03). | **F7-5.** Shrinks the group that can reach UAT data without a login. | Adeola Balogun; Security Operations | W3 D3 to D5 |
| **P2** C-27 | **Reassess UAT controls.** Defender for SQL on `sqldb-uat` while it holds production data. Policy from audit-only to enforce for auditing and diagnostics in non-production. Private access only. Entra-only administration where possible. | **F7-3, F7-4.** Adds detection and removes the preventable paths. The Defender cost is FinServe's call. | Cloud platform; CISO | Plan this week; implement in two weeks |
| **P2** C-28 | **Review the refresh process.** Write down where it runs. Replace static credentials with a managed identity or vault-held secrets. Use two accounts: read-only on production, write on UAT only. Mask in a staging database and swap it in. Alert on runs outside the window. | **F7-1, F7-2, F7-7.** Removes the shared credential, the unmasked interval and the undocumented route. | Adeola Balogun; DBA | Two weeks |

#### Long-term

| ID | Action | Finding and how it helps | Owner | Timing and caution |
|---|---|---|---|---|
| **P3** C-29 | **Replace production data in UAT** with synthetic or irreversibly anonymised data. | **F7-2.** Removes the data that makes UAT a Restricted store. | CTO (Elliot Vance); Cloud Platform Lead | Weeks. After C-30 is agreed. |
| **P3** C-30 | **Redesign reconciliation testing** so it does not need production personal data. (a) Tokenise NI number, account number, sort code, date of birth and address consistently, so joins and totals still reconcile. (b) Compare against production figures inside production and export only control totals. (c) Use synthetic volumes for load. | **F7-2, I7-N3.** Answers the engineering reason for leaving the data in (I7-N3) with a method, not a refusal. GRC owns the position on the test pack. SOC supports it with the exposure evidence. | GRC lead; Cloud Platform Lead; test owners | Weeks |
| **P3** C-31 | **Remove static, shared and cross-zone credentials across the estate.** Secret-scan scripts and configuration on legacy hosts, starting with `/opt/finrecon`. One account per purpose and per zone. A rotation schedule. Include the Meridian credential (C-08). | **F7-1.** Stops the next plain-text credential from being found in a directory listing. | Infrastructure; Security Operations | Weeks |
| **P3** C-32 | **Least privilege and PIM** on every subscription (standing Owner and Contributor, E2 §4). | **F7-5.** | CTO; Cloud Platform Lead | Weeks |
| **P3** C-33 | **Monitoring.** Onboard the DC-SLO hosts. Keep SQL audit hot for 60 days and cold for a year. Build DET-01, DET-06 and the Section 28 row 9 detections, plus alerts for a service account used from a new source. | **F7-3.** FinServe found this through a third party after 33 hours. | Security Operations | Quarter |

### 32.9 Cross-team coordination

**The two findings are about the same database.** GRC holds a compliance finding about what the UAT refresh masks in `sqldb-uat`. The SOC holds a firewall log of a host connecting to `sqldb-uat` (10.30.2.14, `sub-nonprod`; I6-A3, T11). That is one database. SOC sends this section to GRC today and asks for a short joint session, because neither team can answer the other's question alone: GRC cannot say whether the database was reached, and SOC cannot say what the exposure means in law. I do not assume that GRC has finished a DPIA.

**The engagement plan already put this on the table.** Its joint touchpoints (`06-DELIVERABLES/GRC/Engagement Plan - Project Sentinel (3).docx`, item 2, the UAT data refresh F10) split it in two. GRC assesses the data protection implications of unmasked National Insurance numbers in non-production. SOC assesses the standing exception CHG-2024-0881, which lets UAT reach production SQL, and whether that path is monitored. **SOC's answer to its half is that it is not.** The flows cross Azure Firewall, which logs them for 60 days (E7 §1, §4). The only analytics rule on Azure Firewall data counts blocked traffic (E8), so a permitted flow between the zones raises nothing. The managed instance's audit is on, but it sits in storage outside Sentinel (E7 §3). The plan also commits both teams to escalate urgent findings to the CISO in writing as soon as they are identified (C-23).

**What SOC shares**

| # | What | Evidence | Status | What GRC can use it for | Do not infer |
|---|---|---|---|---|---|
| 1 | Unauthorised SFTP access to the settlement host | I6-A1, I6-A2; Sections 14 and 15 | Logins **proven**. "Unauthorised" **assessed**. | Potential unauthorised access; the vector | That the log is complete (13.3) |
| 2 | The actor asked to open `refresh_uat.ps1` | I6-A2, 03:53:18 | Request **proven**. Receipt **assessed, moderate**. | A credential exposure; a control weakness | That the actor has the credential |
| 3 | A permitted connection from that host to `sqldb-uat` | I6-A3 | Network permit **proven**. Login **unknown**. | Whether the database was reached | That a flow is a login |
| 4 | Potential exposure of 181,402 customer records | I7-A1; E2 §3 | A ceiling, from design | Data subjects, categories, risk to individuals | That any record was accessed |
| 5 | Missing SQL audit evidence | I6-A3; I7-A1; E7 §1 | Nothing in Sentinel. Elsewhere **unknown**. | Why "no evidence of access" is not reassurance | That absence means no access (32.5) |
| 6 | The revised impact assessment | 32.3 to 32.6 | **Assessed.** Rating Critical. | Risk rating, control weaknesses, treatment | That the rating means harm occurred |
| 7 | Evidence still required | ER-21 to ER-32 | Open | What will change the picture, and by when | That silence from SOC means a clean result |

**How the SOC's findings support GRC's assessment**

| GRC assessment | What SOC provides |
|---|---|
| Data protection risk | The categories (D1 to D3), the population (181,402), the fact that masking leaves the data personal (32.1), and the unmasked interval and restore points (C11). |
| Potential unauthorised access | The chain A to E, with each link's status (32.2); the exposure ladder (32.5); the list of what cannot be ruled out (32.4.3). |
| Potential customer impact | The consequences (32.3) and the ceiling. No claim of harm. |
| Security control weaknesses | F7-1 to F7-7: a shared plain-text credential, no UAT detection, an over-broad firewall rule, 21 standing Contributors, short and overwritten evidence, and documents that disagree with the script. |
| Risk treatment recommendations | C-17 to C-33, with owners; and a position on reconciliation testing (C-30) that GRC can adopt or change. |

**Dates GRC may want.** Whether and when FinServe became aware of a personal data breach is for the DPO (Section 27.2). Arithmetic only: 72 hours after Mon 19 Oct 07:12 UTC (Meridian's alert) is Thu 22 Oct 07:12 UTC. 72 hours after Wed 21 Oct 10:54 UTC (UAT contents confirmed) is Sat 24 Oct 10:54 UTC. SOC does not choose between them.

**What SOC asks of GRC**

- Check the categories and counts above against your data map and tell us where they differ.
- Share the decision record PROD-TEST-042 and the Lighthouse acceptance. SOC has not seen either.
- Tell us if your draft treats UAT as anonymised or pseudonymised. The evidence supports neither (32.1).
- Give us the risk register reference so SOC can cite it.
- Agree a daily 15-minute update until ER-21 to ER-26 close.

### 32.10 Conclusion

**What is confirmed.** An unauthorised actor logged in to the settlement host and asked to open `refresh_uat.ps1`. The platform team's extract of that script holds a plain-text database credential used for both production and UAT. UAT holds a copy of production for 181,402 customers, with only names and email addresses masked. The host connected to UAT three times 18 minutes later. Nothing in UAT is audited or monitored in any way we can see.

**The worst case.** The actor used that credential to read all of UAT and possibly production, and took it out of the estate: about 180,000 people's NI numbers, dates of birth, addresses, account details and transactions, plus a persistent foothold. This is a ceiling. None of it is shown.

**What remains unknown.** Whether the credential was received, used or valid; what the 04:11 connections did; whether production was reached; whether anything left; how long the credential has been exposed; and who else holds it. The evidence we hold cannot answer any of these either way.

**What should happen now.** Capture the credential's metadata, then rotate it on both sides today (C-17). Suspend the nightly refresh before 02:00 on Thursday (C-18). Restore UAT to 18 October and read Query Store before Sunday 25 October 04:11 (C-19). Read the production audit for the account (C-20). Tell the CISO and send GRC this section today (C-23).

### 32.11 Changes to earlier sections

Nothing is deleted. Earlier text stays where it was written. These are the places where Inject 07 adds to it.

| Section | Earlier statement | Status now | Note |
|---|---|---|---|
| Header, revision notice, 1 | Rating: Critical (Inject 06) | **Reconfirmed** | Marked "Update (Inject 07)" |
| 15 (row 03:53:18) and 16.3 | `refresh_uat.ps1`: purpose and contents **[U]** | **Update** | Now known from an extract (I7-A2, T14) |
| 17.4 | X1 to X4, "I do not rank" | **Extended** | X5 and X6 added; X2 revised (32.2). Still not ranked. |
| 19.2, rows 1 and 9 | What the connection did; contents of six files | **Row 1 extended, row 9 reduced by one file** | 32.4.3 |
| 21.2 | Conditions that would lower the rating to High | **Replaced** | 32.6. The old conditions could not be met as written. |
| 22.2 | C-08 item 3, C-09, C-10, C-14 | **Sharpened** | C-17 to C-22, C-24 |
| 27 | Handoff to GRC | **Extended** | 32.9 |
| 30 | Questions 12 to 20 | **Extended** | Questions 21 to 29 in 32.12 |

**Unchanged:** Sections 1 to 11 other than the notes above, the timeline in Section 15, the path in Section 16.1, Section 20, and the Meridian-facing actions in Section 22.

### 32.12 Assumptions, queries and questions added by Inject 07

**Assumptions** (continuing T1 to T12)

| # | Assumption or caveat | If it is wrong |
|---|---|---|
| T13 | **Calendar and time.** I7-A1 is dated Wednesday 21 October, 10:54, with no zone. I treat it as UTC (as T1). T5 maps W3 D2 to Tuesday 20 October. I use the email's date. | Counts of days remaining before expiry move by one day. The expiry dates in this section do not move. |
| T14 | **Same file.** I7-A2 is "held on the DC-SLO host" and does not name it. I6-A2 shows a file of the same name in `/opt/finrecon/conf` on `sftp-slo`. I treat them as the same file. The header "Last modified 2024-03-11" is a comment inside the file, not a file-system time. There is no hash. | If the file differs, the 03:53:18 request may not have exposed this credential. The plain-text credential in the platform's copy still needs rotating. |
| T15 | **Open is not read.** An open-for-read line records a request. With no `close` line or byte count, completion and volume are not shown (T10). | If the full log shows completed transfers, rung 3 becomes proven. |
| T16 | **Where the job runs.** I7-A2 does not say which host executes the scheduled task. "Scheduled task" is Windows wording, and `sftp-slo` logs read as OpenSSH on Linux (operating system Unknown, Coverage-Gaps Q8). I do not assume the refresh runs on `sftp-slo`. The 02:00 may be host-local time. | If it runs on `sftp-slo`, X2 gains weight. If elsewhere, the script on `sftp-slo` is a copy and the question is why. |
| T17 | **"Everything else".** I7-A1 says everything other than three fields arrives as in production. I treat every other column and table as unmasked, including phone numbers if held. E4 lists F10 as D1 and D3. E4 §2 shows D5 on the managed instance, and it is not confirmed as copied. | If more is masked than I7-A1 says, the exposure is smaller. |
| T18 | **Population.** 181,402 is the row count at about 21 October. The count on 18 October is not supplied. I use it as the best available figure. | The figure is likely close, and could be a little higher or lower. |
| T19 | **Product behaviour** (general knowledge, not FinServe documents; the DBA should confirm). (a) An Azure Firewall network-rule row records a rule match for a flow, not login, statements, bytes or duration. (b) Query Store buckets are 60 minutes by default and are stored in the database, so a point-in-time restore brings them back. (c) Managed-instance audit records carry client address, principal and application name when the relevant action groups are on. (d) Changing a SQL login's password overwrites its password-last-set time. (e) A subscription Contributor can change SQL auditing, firewall and administrator settings, export or copy a database, and deploy or run code in an App Service, without a database login. | Each affects the matching request: (a) ER-25, (b) ER-21, (c) ER-24, (d) ER-22, (e) ER-30 and ER-31. |

**Queries** (continuing Q19; none run; names to be checked in the workspace; read-only)

**Q20. Everything between the host and UAT, 17 Oct 22:00 to 19 Oct 08:00 (Sentinel)**

```kql
AZFWNetworkRule
| where TimeGenerated between (datetime(2026-10-17 22:00) .. datetime(2026-10-19 08:00))
| where SourceIp == "172.20.14.30" or DestinationIp == "10.30.2.14"
| project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Action, Rule
| order by TimeGenerated asc
```

*Expect:* flows around the refresh on 18 and 19 October if the job runs from this host, with the pattern visible by hour. Any Deny. Only the three flows, if it does not. Compare with the window and filter behind I6-A3, which are not stated.

**Q21. Flows to any production SQL address from the host and from the CHG-2024-0881 range, 60 days (Sentinel)**

```kql
AZFWNetworkRule
| where TimeGenerated > ago(60d)
| where SourceIp == "172.20.14.30" or Rule has "CHG-2024-0881"
| where DestinationPort == 1433 or DestinationPort == 3342 or DestinationPort between (11000 .. 11999)
| summarize Flows = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by SourceIp, DestinationIp, DestinationPort, Action, Rule, Hour = hourofday(TimeGenerated)
| order by DestinationIp asc, SourceIp asc, Hour asc
```

*Expect:* flows at a regular hour to the production managed instance's address (the platform team will recognise it) if the refresh runs from the host, or from the UAT App Service's range under CHG-2024-0881 if it runs as the documents say. A source outside both, or an hour outside the refresh, is new. None from the host means the job does not run there, or the flows do not cross Azure Firewall. The rule name is as recorded in E1 §3.1 and must be checked in the workspace.

**Q22. Is the firewall log complete around 04:11? (Sentinel)**

```kql
AZFWNetworkRule
| where TimeGenerated between (datetime(2026-10-18 00:00) .. datetime(2026-10-18 06:00))
| summarize Rows = count() by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
```

*Expect:* continuous counts. A gap around 04:11 means "three rows" understates what happened.

**Q23. Production audit for the refresh account (T-SQL, run by a DBA, read in place)**

```sql
-- Illustrative. Check the path and columns. Do not select the statement column into any shared output: it can hold data.
SELECT event_time, action_id, succeeded, server_principal_name, client_ip, application_name, host_name
FROM sys.fn_get_audit_file('https://<audit-storage>.blob.core.windows.net/<container>/<instance>/*', DEFAULT, DEFAULT)
WHERE server_principal_name = '<refresh-account>'
   OR client_ip IN ('172.20.14.30', '45.83.220.61')
ORDER BY event_time;
```

*Expect:* logins from the job's known source at the job's hour. Anything else is the first direct evidence of use. If the authentication action groups are off, the result is empty and means nothing.

**Q24. The refresh account's metadata, before rotation (T-SQL, run by a DBA)**

```sql
-- Illustrative. Run on sqlmi-prod and on the UAT server. Read-only. Run BEFORE the password is changed.
SELECT name, create_date, modify_date,
       LOGINPROPERTY(name, 'PasswordLastSetTime') AS password_last_set
FROM sys.sql_logins
WHERE name = '<refresh-account>';

SELECT p.name AS member, r.name AS role_name
FROM sys.server_role_members AS m
JOIN sys.server_principals AS r ON r.principal_id = m.role_principal_id
JOIN sys.server_principals AS p ON p.principal_id = m.member_principal_id
WHERE p.name = '<refresh-account>';
```

*Expect:* the date the password was last set, which bounds the exposure window, and the roles, which set the real worst case on each side. On the logical server, read database roles from `sys.database_role_members` instead.

**Q19 additions** (read-only, run by a host administrator with the existing Q19 commands)

```bash
sshd -T 2>/dev/null | grep -E "allowtcpforwarding|permitopen|permittunnel|gatewayports"
which pwsh powershell sqlcmd python3 2>/dev/null
grep -h -E "Oct 18 04:(0[5-9]|1[0-9])" /var/log/auth.log* | sort
grep -h -E "close .*(deliver.cfg|refresh_uat.ps1)" /var/log/auth.log* /var/log/*sftp* 2>/dev/null
```

*Expect:* whether forwarding is permitted; whether the host has any tool that could run the script; every `sshd` line from 04:05 to 04:19 (adjust for T6); and `close` lines with byte counts for the two files.

**Questions for FinServe** (continuing Section 30, through the mentor)

| # | Question | Why it matters |
|---|---|---|
| 21 | Which host runs the nightly refresh task, in which time zone is 02:00 set, and how long does the copy take? | X2; reads Q20 and Q21 correctly (T16). |
| 22 | Who or what else uses the refresh account: jobs, hosts, people, the UAT test pack? | I7-C8; the baseline for "unexpected use". |
| 23 | What can the account do on production and on UAT? | The real worst case (32.3). |
| 24 | Has its password been changed since 11 March 2024, and by whom? | I7-C7; the length of the exposure window. |
| 25 | Does the UAT test pack run from the FinRecon host, and when? | X5. |
| 26 | Is public network access enabled on the UAT server, and is the `sqlmi-prod` public endpoint enabled? | I7-C5; whether the host was needed at all. |
| 27 | Can we read PROD-TEST-042, and who accepted the risk at Lighthouse? | I7-N3; GRC. |
| 28 | Is FinServe's own incident severity scale available? (Section 11, question 6 is still open.) | 32.6. |
| 29 | Does the nightly refresh really use the CHG-2024-0881 route to `sqlmi-prod`, from which source range, and why has the exception no expiry? | I7-C5; the second route into production SQL (32.3). |
