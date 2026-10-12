# Supplier Register - Project Sentinel

FinServe Digital Bank Ltd

## Approach

Built from 04-Data-Flow.md sections 3 and 5, cross-referenced with the stakeholder profiles and architecture documents. Not derived from FinServe's existing 63-entry supplier register, which tracks contract renewal dates but has no fields for data categories, processing location, DPA status or transfer basis.

Scope: suppliers that receive, process or have access to customer or employee data (categories D1 through D7). Suppliers providing only non-data services (cleaning, catering, office supplies) are excluded.

### Risk assessment scale

| Rating | Definition |
| --- | --- |
| Critical | Missing or inadequate controls that create an immediate compliance exposure or could prevent regulatory notification within required timescales |
| High | Controls exist but are materially incomplete; remediation needed within the current quarter |
| Medium | Controls are in place but have documented weaknesses or gaps in coverage |
| Low | Controls are adequate; routine monitoring sufficient |

## Register

### S-01: Corebridge Technologies Ltd

| Field | Detail |
| --- | --- |
| Service | Core banking platform, card issuing and processing, transaction posting, end-of-day settlement extracts |
| Data categories | D1 (identity), D3 (financial), D4 (card, PAN held by Corebridge) |
| Processing location | Leeds (primary), Dublin (DR) |
| Cross-border transfer | Yes, Dublin DR site. Covered by UK adequacy regulations for the EEA. Microsoft DPA and Corebridge MSA both contain UK GDPR processor terms. |
| Contract | MSA 2021, renewed 2024 |
| DPA | Yes |
| Material outsourcing (PRA SS2/21) | Yes. On the material outsourcing register. |
| FinServe criticality rating | High |
| Risk assessment | Medium. Contract and DPA are in place. DR site transfer is covered. Gap: application logs held by Corebridge are accessible only by ticket, limiting FinServe's ability to investigate incidents in its own customer data. Sentinel connector for Corebridge does not exist. |

### S-02: Microsoft

| Field | Detail |
| --- | --- |
| Service | Azure (IaaS/PaaS), Microsoft 365, Entra ID, Defender, Intune |
| Data categories | All (D1 through D7) |
| Processing location | uksouth and ukwest (Azure); UK data residency for M365 core services |
| Cross-border transfer | No. Both regions are domestic. The 2024 legal opinion covers this arrangement. |
| Contract | Microsoft Product Terms + DPA |
| DPA | Yes |
| Material outsourcing (PRA SS2/21) | Yes. On the material outsourcing register. |
| FinServe criticality rating | High |
| Risk assessment | Low. Contract, DPA, legal opinion and domestic processing all in place. Standard residual risk of concentration on a single hyperscaler. |

### S-03: IDVerify UK Ltd

| Field | Detail |
| --- | --- |
| Service | Electronic identity verification at customer onboarding (document and biometric check) |
| Data categories | D2 (identity documents: passport/licence images, NI number) |
| Processing location | London |
| Cross-border transfer | No |
| Contract | SaaS agreement 2023 |
| DPA | Yes |
| Material outsourcing (PRA SS2/21) | No |
| FinServe criticality rating | Medium |
| Risk assessment | Low. Contract, DPA and domestic processing in place. Supplier due diligence performed at procurement. |

### S-04: Textway Communications

| Field | Detail |
| --- | --- |
| Service | SMS delivery for SCA one-time passcodes and transaction alerts (\~62,000 messages/day) |
| Data categories | D1 (phone number), D3 (transaction amount in message body) |
| Processing location | London (primary); routes through a Singapore aggregator |
| Cross-border transfer | Yes, Singapore. No adequacy regulations. No IDTA and no UK Addendum in place. Identified in 2025 data mapping; not yet assessed. |
| Contract | Reseller terms only (standard T&Cs) |
| DPA | No |
| Material outsourcing (PRA SS2/21) | No, but arguably should be assessed given SCA dependency. Textway is the sole provider of OTP for payment initiation (IBS-1). No fallback path configured. |
| FinServe criticality rating | Low |
| Risk assessment | Critical. No DPA despite processing D1 and D3 data. No transfer mechanism for the Singapore routing. Onboarded by marketing for campaigns in 2022 and extended to transactional OTP without re-assessment. FinServe rates it Low; the architecture shows it is a single point of failure for IBS-1 (making payments, 4-hour tolerance). A Textway outage stops new payment initiation. |

### S-05: Meridian Trust (partner bank)

| Field | Detail |
| --- | --- |
| Service | Settlement file exchange (end-of-day, nightly) |
| Data categories | D3 (financial: settlement data) |
| Processing location | London |
| Cross-border transfer | No |
| Contract | Interbank agreement 2019, inherited from Kestrel |
| DPA | No. Agreement pre-dates UK GDPR and contains no processor clauses. |
| Material outsourcing (PRA SS2/21) | No |
| FinServe criticality rating | High |
| Risk assessment | High. No DPA despite receiving D3 data nightly. Static SFTP credential not rotated since 2019 (in plaintext in config). The interbank agreement pre-dates UK GDPR and has never been updated. Meridian Trust's own 2024 security review recommended key-based authentication; FinServe deferred it. |

### S-06: Solvex Systems (FinRecon)

| Field | Detail |
| --- | --- |
| Service | FinRecon reconciliation desktop tool; vendor support from Bengaluru |
| Data categories | D3 (financial: reconciliation data visible during processing and support sessions) |
| Processing location | On-premises (DC-SLO) for the tool itself; vendor support access from Bengaluru, India |
| Cross-border transfer | Yes, India (during support sessions). No IDTA in place. The 2024 India adequacy regulations do not cover this type of processor transfer. |
| Contract | Licence agreement 2023 |
| DPA | No |
| Material outsourcing (PRA SS2/21) | No |
| FinServe criticality rating | Not on the register |
| Risk assessment | Critical. Not on FinServe's supplier register at all. No DPA. No IDTA for the India transfer. Vendor support sessions give Solvex engineers sight of D3 financial data. The FinRecon tool authenticates to Exchange Online via basic auth (IMAP), requiring a Conditional Access exclusion that has been renewed twice. The 2024 legal opinion did not consider this transfer path. |

### S-07: Cloudflare

| Field | Detail |
| --- | --- |
| Service | External DNS resolution and DDoS protection at the edge of the customer traffic path |
| Data categories | D5 (behavioural: request metadata, IP addresses, headers inspected for DDoS filtering) |
| Processing location | Global anycast network; UK edge nodes present |
| Cross-border transfer | Yes, by design. Cloudflare operates a global network and traffic may be inspected at edge nodes outside the UK. |
| Contract | Not inspected during this review |
| DPA | Not confirmed. Cloudflare publishes a standard DPA; whether FinServe has signed it is not evidenced in the architecture documents. |
| Material outsourcing (PRA SS2/21) | No, but sits in the customer traffic path for IBS-1, IBS-2 and IBS-3. |
| FinServe criticality rating | Low (S-47 on their register, under "Website hosting and CDN", £11,500 annual value) |
| Risk assessment | Medium. The service is in the critical path but FinServe treats it as a website vendor. The processing location, DPA status and transfer basis need confirmation. The criticality rating understates the operational dependency. |

## Summary of findings

Two suppliers rated Critical, one High, two Medium, two Low.

### Comparison with FinServe's existing register

FinServe's register has 63 entries but tracks only name, contract owner, annual value, renewal date and criticality (high/medium/low). It has no field for data categories received, processing location, DPA status or transfer basis. It cannot answer a data protection question.

Specific discrepancies:

- **Solvex Systems does not appear at all.** A supplier with access to D3 financial data and a cross-border support path to India is missing from the register entirely.
- **Textway is rated Low.** The architecture shows it is a single point of failure for SCA on payment initiation (IBS-1). It has no DPA and an unassessed cross-border transfer through Singapore.
- **No supplier has a recorded DPA status.** The register has no field for it. Of the six data-processing suppliers reviewed here, two have no DPA (Textway, Solvex), one has a pre-GDPR agreement with no processor clauses (Meridian Trust), and three are adequately covered (Corebridge, Microsoft, IDVerify).
- **No supplier has a recorded transfer basis.** Two active cross-border transfers (Textway to Singapore, Solvex to India) have no IDTA or UK Addendum. The 2024 legal opinion covered Microsoft only.

### Potential notification considerations

The Textway and Solvex transfer paths may require assessment under UK GDPR Chapter V. The absence of transfer mechanisms for active data flows is a compliance gap that Legal, the DPO and Compliance should assess for any notification or remediation obligation. This register records the finding; the regulatory interpretation and any notification decision rest with FinServe management.
