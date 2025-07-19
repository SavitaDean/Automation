# Email Threat Analysis Automation Tool

This Python-based tool automates the analysis of suspicious emails, streamlining a key workflow for SOC analysts. It extracts and evaluates various components of an email to assess the likelihood of phishing, spoofing, or other forms of email-based attacks.

 Features

- **Email Header Parsing**  
  Extracts metadata like sender, subject, reply-to address, received path, and more.

- **SPF, DKIM, and DMARC Evaluation**  
  Analyzes the results of SPF, DKIM, and DMARC to determine whether the sender’s identity can be trusted.

- **URL and Attachment Scanning**  
  - Checks URLs and file attachments using the VirusTotal API.
  - Flags domains and IPs via AbuseIPDB.
- **Attachment Hashing**
  - Hashes attachment before scanning

- **Sender Domain and IP Intelligence**  
  - Retrieves sender's IP address and checks its reputation.
  - Queries WHOIS information.
  - Performs blacklist lookups.

- **Spelling and Grammar Analysis**  
  Assesses email body for spelling and grammar errors, which can indicate phishing or low-effort scam attempts.


