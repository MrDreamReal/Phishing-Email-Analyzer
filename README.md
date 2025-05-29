# Phishing-Email-Analyzer

🛡️ Phishing Email Analyzer (PowerShell)

PhishingEmailAnalyzer.ps1 is a PowerShell-based phishing detection script for cybersecurity analysts, SOC teams, and incident responders. It performs deep analysis on .eml email files to identify spoofing attempts, phishing links, malicious attachments, urgency-based social engineering, and other common phishing tactics.
🚀 Features

🔍 Header Analysis

    Checks for mismatched From and Return-Path headers

    Detects missing or failed SPF, DKIM, and DMARC records

✉️ Body Analysis

    Scans for urgency/social engineering keywords

    Identifies spelling or grammar issues commonly found in phishing emails

🔗 Link Analysis

    Extracts and analyzes all URLs in the email body

    Flags suspicious domains, IP-based URLs, and URL shorteners

    Detects known phishing domains via regex pattern matching

📎 Attachment Analysis

    Detects potentially malicious file extensions (e.g., .exe, .vbs, .jar)

    Flags double extensions (e.g., invoice.pdf.exe)

    Identifies all attachments via MIME headers

📊 Threat Scoring & Risk Assessment

    Assigns a threat score based on findings

    Categorizes the email risk: Minimal, Low, Medium, or High Risk


    
