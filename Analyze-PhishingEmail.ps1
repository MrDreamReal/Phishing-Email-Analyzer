function Analyze-PhishingEmail {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$FilePath
    )

    begin {
        # Define phishing domains regex pattern
        $phishingDomainsPattern = @(
            "secure-document\.com",
            "account-verification\.net",
            "login-update\.org",
            "verify-identity\.info"
        ) -join "|"

        # Suspicious extensions
        $maliciousExtensions = @(".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".hta")

        # Urgency keywords for phishing
        $urgencyKeywords = @(
            "urgent", "immediate action required", "account suspended", "verify now",
            "security alert", "unauthorized login", "password expired", "click below",
            "limited time", "your account", "dear customer", "dear user"
        )
    }

    process {
        try {
            if (-not (Test-Path $FilePath)) {
                Write-Warning "File not found: $FilePath"
                return
            }

            # Read entire email file
            $emailContent = Get-Content $FilePath -Raw

            # Split headers and body correctly
            $splitIndex = $emailContent.IndexOf("`r`n`r`n")
            if ($splitIndex -lt 0) {
                $headers = $emailContent
                $body = ""
            } else {
                $headers = $emailContent.Substring(0, $splitIndex)
                $body = $emailContent.Substring($splitIndex + 4)
            }

            $analysisResults = @()
            $threatScore = 0

            $analysisResults += "===== HEADER ANALYSIS ====="

            # Extract From header and Return-Path
            $fromHeader = ([regex]::Match($headers, "(?m)^From:\s*(.+)$")).Groups[1].Value.Trim()
            $returnPath = ([regex]::Match($headers, "(?m)^Return-Path:\s*<(.*)>")).Groups[1].Value.Trim()

            if ($fromHeader -and $returnPath -and ($fromHeader -notlike "*$returnPath*")) {
                $analysisResults += "WARNING: From header ($fromHeader) doesn't match Return-Path ($returnPath) - possible spoofing"
                $threatScore += 20
            }

            # Check SPF, DKIM, DMARC presence in headers
            if ($headers -notmatch "spf=pass") {
                $analysisResults += "WARNING: SPF check failed or missing - possible spoofing"
                $threatScore += 15
            }
            if ($headers -notmatch "dkim=pass") {
                $analysisResults += "WARNING: DKIM check failed or missing - possible spoofing"
                $threatScore += 15
            }
            if ($headers -notmatch "dmarc=pass") {
                $analysisResults += "WARNING: DMARC check failed or missing - possible spoofing"
                $threatScore += 15
            }

            # Body analysis
            $analysisResults += "`n===== BODY ANALYSIS ====="

            # Urgency keyword count
            $urgencyCount = 0
            foreach ($keyword in $urgencyKeywords) {
                if ($body -imatch [regex]::Escape($keyword)) {
                    $urgencyCount++
                    $analysisResults += "Found urgency keyword: $keyword"
                }
            }
            if ($urgencyCount -gt 0) {
                $threatScore += ($urgencyCount * 2)
                $analysisResults += "Total urgency keywords found: $urgencyCount"
            }

            # Basic grammar/spelling checks (expand as needed)
            $grammarIssues = @()
            if ($body -imatch "dear (customer|user|sir|madam)") {
                $grammarIssues += "Generic greeting"
            }
            if ($body -imatch "plese click") {
                $grammarIssues += "Spelling error: 'plese click'"
            }
            if ($grammarIssues.Count -gt 0) {
                $threatScore += 10
                $analysisResults += "Grammar/spelling issues detected: $($grammarIssues -join ', ')"
            }

            # Link analysis
            $analysisResults += "`n===== LINK ANALYSIS ====="
            $links = [regex]::Matches($body, "(http|https)://([\w\.-]+)([\w\.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?")
            $analysisResults += "Found $($links.Count) link(s) in the email body."

            $suspiciousLinks = 0
            foreach ($link in $links) {
                $url = $link.Value

                # URL shorteners
                if ($url -match "(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly)") {
                    $analysisResults += "WARNING: URL shortener detected - $url"
                    $suspiciousLinks++
                    $threatScore += 5
                }

                # Known phishing domains
                if ($url -match $phishingDomainsPattern) {
                    $analysisResults += "WARNING: Known phishing domain detected - $url"
                    $suspiciousLinks++
                    $threatScore += 25
                }

                # IP address in URL
                if ($url -match "\b\d{1,3}(\.\d{1,3}){3}\b") {
                    $analysisResults += "WARNING: IP address found in URL - $url"
                    $suspiciousLinks++
                    $threatScore += 15
                }
            }
            if ($suspiciousLinks -eq 0) {
                $analysisResults += "No suspicious links detected."
            }

            # Attachment analysis
            $analysisResults += "`n===== ATTACHMENT ANALYSIS ====="
            if ($emailContent -match "Content-Disposition: attachment") {
                $attachments = [regex]::Matches($emailContent, "filename=['""]?([^'""\s;]+)['""]?")
                foreach ($attachment in $attachments) {
                    $filename = $attachment.Groups[1].Value
                    $analysisResults += "Found attachment: $filename"

                    $ext = [System.IO.Path]::GetExtension($filename).ToLower()
                    if ($maliciousExtensions -contains $ext) {
                        $analysisResults += "WARNING: Malicious attachment extension detected: $filename"
                        $threatScore += 30
                    }

                    if ($filename -match "\.[^.]+\.[^.]{2,4}$") {
                        $analysisResults += "WARNING: Double extension detected: $filename"
                        $threatScore += 25
                    }
                }
            } else {
                $analysisResults += "No attachments found."
            }

            # Final assessment
            $analysisResults += "`n===== FINAL THREAT ASSESSMENT ====="
            $analysisResults += "Threat score: $threatScore / 150"

            if ($threatScore -ge 70) {
                $analysisResults += "CONCLUSION: HIGH RISK - Likely phishing email."
            } elseif ($threatScore -ge 40) {
                $analysisResults += "CONCLUSION: MEDIUM RISK - Suspicious indicators found."
            } elseif ($threatScore -ge 20) {
                $analysisResults += "CONCLUSION: LOW RISK - Some suspicious elements."
            } else {
                $analysisResults += "CONCLUSION: MINIMAL RISK - No strong phishing indicators."
            }

            # Output result as a single string
            $analysisResults -join "`n"

        } catch {
            Write-Error "Error analyzing email file '$FilePath': $_"
        }
    }
}

# Example usage:
# Get-ChildItem -Path "C:\emails\" -Filter *.eml | Analyze-PhishingEmail | Out-File analysis-results.txt