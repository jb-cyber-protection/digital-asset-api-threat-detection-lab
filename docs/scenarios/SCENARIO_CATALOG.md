# I-003 Threat Scenario Catalog

## Scope
This catalog defines cloud-first threat scenarios for digital-asset API and algorithmic trading environments.

## Scenario Index
| Scenario ID | Name | Priority | Core Signal |
| --- | --- | --- | --- |
| SCN-001 | API Key Replay From New Geography | High | Same key used from unusual geos + auth failure prelude |
| SCN-002 | Credential Stuffing Against API Authentication | High | Failure burst across many accounts then success |
| SCN-003 | Suspicious Withdrawal Request Chain | Critical | High-value withdrawal from novel context |
| SCN-004 | Bot Hijack Causing Order-Book Manipulation Signals | High | Create/cancel burst deviates from profile baseline |
| SCN-005 | Cloud Service Token Misuse in Trading Context | High | Key/token usage from non-standard infra context |
| SCN-006 | Data Exfiltration-Like API Enumeration | Medium | High-volume read endpoint burst with repetitive access |

## Trigger Logic and IOC Expectations
### SCN-001 API Key Replay From New Geography
- Trigger conditions:
  - same `api_key_id` used from multiple `ip_country` values inside a short window
  - failed authentication before suspicious key usage
  - endpoint behavior shift into trade actions
- IOC expectations:
  - Primary: key id, source IP, country, user-agent
  - Secondary: request id, account/bot id, endpoint sequence
- Expected analyst response:
  - validate account baseline, isolate affected key, escalate if trade operations occurred

### SCN-002 Credential Stuffing Against API Authentication
- Trigger conditions:
  - high `auth.login.failure` volume from one IP
  - multiple accounts targeted
  - eventual `auth.login.success`
- IOC expectations:
  - Primary: attacking IP, targeted accounts, failure reasons
  - Secondary: user-agent, region, request IDs
- Expected analyst response:
  - eliminate scanner noise, identify compromised account, escalate when post-failure sessions exist

### SCN-003 Suspicious Withdrawal Request Chain
- Trigger conditions:
  - uncommon `withdrawal.request` for key/account
  - amount outside baseline
  - novel geo/region context
- IOC expectations:
  - Primary: asset, amount, key ID, source geo
  - Secondary: network, destination type, request IDs
- Expected analyst response:
  - immediate withdrawal hold/key containment if suspicious, escalate with auth + transaction timeline

### SCN-004 Bot Hijack Causing Order-Book Manipulation Signals
- Trigger conditions:
  - order burst and cancel ratio deviation from profile baseline
  - concurrent context shift (geo or user-agent)
- IOC expectations:
  - Primary: bot/account IDs, order burst set
  - Secondary: symbol focus, key ID, geolocation
- Expected analyst response:
  - compare against normal strategy behavior, isolate if unexplained, escalate for manipulation risk

### SCN-005 Cloud Service Token Misuse in Trading Context
- Trigger conditions:
  - token/key usage from unusual infrastructure region
  - user-agent shift and out-of-window activity
- IOC expectations:
  - Primary: key ID, region, user-agent, endpoint
  - Secondary: IP, request IDs, account context
- Expected analyst response:
  - correlate with deployment/IAM changes, determine blast radius, escalate if unauthorized

### SCN-006 Data Exfiltration-Like API Enumeration
- Trigger conditions:
  - read endpoint burst from one key
  - repetitive low-latency access
  - atypical source context
- IOC expectations:
  - Primary: endpoint frequency, key ID, latency pattern
  - Secondary: country/region, request IDs
- Expected analyst response:
  - validate operational jobs vs abuse, quantify exposed data scope, escalate if unauthorized collection likely

## Source of Truth
Machine-readable definitions: `data/scenarios/scenario_library.json`.
