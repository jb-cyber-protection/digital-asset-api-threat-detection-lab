# Application Answer Draft

## Prompt
Briefly describe (if not in your Resume) your knowledge and experience within the area of digital assets and/or algorithmic trading.

## Submission-Ready Answer (Concise)
I built a practical digital-asset SOC lab that simulates exchange API activity and algorithmic trading bot behavior (market making, momentum, and arbitrage-like patterns), then detects and triages security threats in that context. The project covers custody-sensitive operations (API key use and withdrawals), ATT&CK-mapped detections across six realistic scenarios, and escalation-ready case handling with timelines, IOCs, and containment decisions. I also implemented tuning metrics to reduce false positives while keeping scenario coverage, which reflects how I approach security monitoring in fast-moving 24/7 trading environments.

## Submission-Ready Answer (Expanded)
My hands-on experience comes from building an end-to-end digital-asset threat detection lab designed around exchange API and algorithmic trading operations. I modeled normal bot behavior for market-making, momentum, and arbitrage-like strategies, including order lifecycle, API usage cadence, and custody-sensitive events like withdrawals. On top of that, I implemented a rule-based detection engine mapped to MITRE ATT&CK for six threat scenarios relevant to cloud-first trading environments (key replay, credential stuffing, suspicious withdrawals, bot hijack patterns, token misuse, and exfiltration-like API enumeration). I then built SOC L1 triage outputs and runbooks to support clean escalation to L2/IR, including timeline reconstruction, IOC context, and containment guidance. Finally, I added measurable tuning workflows to reduce benign alerts and improve signal quality, which mirrors real-world monitoring needs in always-on digital-asset infrastructure.
