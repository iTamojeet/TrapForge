\# TrapForge — Part 3: AEI Engine



\## What This Does

This module is the core novelty of the TrapForge project.

It reads attack logs from the honeypot database and computes

three metrics per attacker session.



\## Components



\### 1. AEI — Attack Engagement Index

Measures how deeply an attacker engaged with the honeypot.

Score: 0 to 10 (Low / Medium / High)



Weights:

\- Session Duration       20%

\- Command Diversity      25%

\- Service Breadth        20%

\- Exploitation Attempts  20%

\- File Transfers         10%

\- Login Attempts          5%



\### 2. AJM — Attack Journey Mapper

Reconstructs the attacker's step-by-step path across services.

Labels each step with an attack phase:

Reconnaissance, Initial Access, Execution,

Exfiltration, Lateral Move, Impact



\### 3. DRS — Deception Resilience Score

Measures how convincingly the honeypot fooled the attacker.

Score: 0 to 10 (Low / Medium / High)



Weights:

\- Persistence           20%

\- Service Spread        25%

\- Phase Diversity       20%

\- Destructive Actions   25%

\- Time Investment       10%



\## Files

\- config.py          : Database connection settings

\- aei\_calculator.py  : Computes AEI per session

\- ajm\_mapper.py      : Maps attack journey per IP

\- drs\_scorer.py      : Computes DRS per session

\- engine.py          : Runs all three together



\## Database Tables

Input  : unified\_logs    (written by Part 2)

Output : session\_scores  (read by Parts 4 and 5)

Output : attack\_journeys (read by Parts 4 and 5)



\## How to Run

Step 1: pip install mysql-connector-python

Step 2: python engine.py



\## Sample Output

sess-C1  91.108.56.77    AEI=7.73 High    DRS=9.27  4 services  10 events

sess-B1  45.142.212.100  AEI=3.64 Medium  DRS=4.96  2 services   7 events

sess-A1  185.220.101.45  AEI=1.42 Low     DRS=2.67  1 service    3 events



\## Integration

Reads from : unified\_logs   (Part 2 writes this)

Writes to  : session\_scores, attack\_journeys (Parts 4 and 5 read these)

