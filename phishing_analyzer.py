
import re
from pathlib import Path
from urllib.parse import urlparse

PROJECT_DIR = Path(__file__).resolve().parent
REPORT_FILE = PROJECT_DIR / "phishing_report.txt"

SUSPICIOUS_WORDS = [
    "urgent",
    "verify your account",
    "account suspended",
    "password expires",
    "claim your prize",
    "click immediately",
    "bank details",
    "confirm your password",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def analyze_email(sender, subject, body):
    findings = []

    sender = sender.strip().lower()
    text = f"{subject} {body}".lower()

    # Basic sender validation
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        findings.append("Sender address format looks invalid.")

    # Check for suspicious language
    for phrase in SUSPICIOUS_WORDS:
        if phrase in text:
            findings.append(
                f"Suspicious wording detected: '{phrase}'"
            )

    # Extract and inspect URLs
    urls = URL_PATTERN.findall(body)

    if not urls:
        findings.append("No HTTP/HTTPS URLs found in the email body.")

    for url in urls:
        clean_url = url.rstrip(".,!?;:)")
        parsed = urlparse(clean_url)
        hostname = parsed.hostname or ""

        if parsed.scheme != "https":
            findings.append(
                f"URL does not use HTTPS: {clean_url}"
            )

        if hostname and (
            hostname.startswith("xn--")
            or ".xn--" in hostname
        ):
            findings.append(
                f"URL contains an internationalized domain label: {clean_url}"
            )

        if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
            findings.append(
                f"URL uses an IP address as its host: {clean_url}"
            )

        if "@" in parsed.netloc:
            findings.append(
                f"URL contains an @ symbol in its network location: {clean_url}"
            )

    if not findings:
        findings.append(
            "No configured warning rules were triggered. "
            "This does not prove the email is safe."
        )

    return findings, urls


def main():
    print("===== PHISHING EMAIL ANALYZER =====")

    sender = input("Enter sender email: ")
    subject = input("Enter email subject: ")
    print("Enter email body (press Enter when finished):")
    body = input()

    findings, urls = analyze_email(sender, subject, body)

    lines = [
        "===== PHISHING EMAIL ANALYSIS REPORT =====",
        f"Sender: {sender}",
        f"Subject: {subject}",
        "",
        "Extracted URLs:",
    ]

    if urls:
        lines.extend(urls)
    else:
        lines.append("None found")

    lines += ["", "Findings:"]

    for finding in findings:
        lines.append(f"- {finding}")

    lines += [
        "",
        "Important: This is a basic rule-based screening tool.",
        "Warnings are indicators, not proof of phishing.",
        "Do not open suspicious links to test them.",
    ]

    report = "\n".join(lines)
    REPORT_FILE.write_text(report, encoding="utf-8")

    print("\n" + report)
    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
