# Incident Report INC-01: Reported phishing email and compromised mailbox session

**Project Sentinel · Inject 04 · SOC Track**

| Item | Detail |
|---|---|
| Client | FinServe Digital Bank Ltd |
| Workstream | Security Operations (SOC) |
| Deliverable | `06-DELIVERABLES/SOC/INC-01-Invoice-Phish.md` |
| Companion | `Detection-Backlog.md`, Section 8 (detection gap: DET-10 and DET-11) |
| References | Sentinel incident 2026-W2D1-0093; service desk ticket SD-2026-4417 |
| Date | 14 October 2026 |
| Prepared by | SOC Team |
| Status | **Provisional.** Built from the three inject artefacts and the existing 04-SOC documents. There is no tenant access and no query has been run. Section 8 lists what would be run and what I expect it to return. |

**How to read this report.** Every statement is tagged.

| Tag | Meaning |
|---|---|
| **[F] Fact** | Stated in an artefact or a source document. The reference is given. |
| **[A] Assessment** | My reasoning from the facts. Not directly evidenced. The reasoning is given. |
| **[U] Unknown** | Cannot be determined from what we hold. The query that would settle it is in Section 8. |

## 1. Summary

- **What happened.** A Finance Operations user, Rachel Oduya (`r.oduya`), received a spoofed "Nadia Ferreira" email and, on the evidence, signed in on an attacker-controlled page. About 100 seconds after her "done" reply, a session using her token appeared from a hosting network in Manchester. Within 23 minutes it had created a concealing inbox rule, read her inbox and the "Settlement Ops (shared)" mailbox, and downloaded two files: `Settlement runbook v4.docx` and `DR-SLO access notes.txt`.
- **Rating.** Sentinel raised it as Medium ("Atypical travel"). I rate it **High, provisional**, rising to **Critical** if `DR-SLO access notes.txt` holds working access details (Section 6).
- **First three actions.** (1) Revoke Rachel's sessions and block sign-in. (2) Disable, not delete, the inbox rule named ".". (3) Copy the DC-SLO SFTP server's local logs off the box and phone Nadia Ferreira and Finance Operations to check no settlement instruction has changed.
- **Decision for the CISO.** Whether to rotate the static DC-SLO SFTP credential before tonight's settlement run, accepting a risk to settlement if it is done badly (Section 7.3).
- **Biggest unknown.** What the two downloaded files contain, and what the attacker did after 08:23:02 (Section 5.3).
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

## 6. Severity

**High, provisional.** Sentinel's rating of Medium reflects only the location anomaly.

**Why High**

- Confirmed account takeover of a Finance Operations user, with MFA defeated rather than avoided.
- Hands-on activity: a concealment rule within three minutes, then targeted mail and file access.
- Two files removed, one of which may open a path into the legacy Slough estate. That path has no Sentinel telemetry, and its credential has not changed since 2019 (E4 §4 as cited in `Coverage-Gaps.md` G3).
- It touches the settlement process, and the threat profile rates BEC against Finance as High.
- The scope is open (Section 5.3), and the same weaknesses were recorded in 2025 and not closed.

**Why not Critical yet.** There is no evidence so far of customer data loss, a payment change, a second compromised account or use of the Slough access.

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

