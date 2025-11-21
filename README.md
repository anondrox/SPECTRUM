# SPECTRUM

**SPECTRUM** is a Domain Technology & CVE Intelligence Scanner designed to help you quickly understand the tech stack and potential CVE exposure of domains you own.

## Features

- Detects backend languages (PHP, Python, Node.js, Ruby, Java, .NET) via headers and cookies.
- Detects common frameworks/CMS (WordPress, Drupal, Joomla, Magento, Laravel, Symfony, etc.).
- Performs best-effort CVE lookup via cve.circl.lu for detected frameworks.
- Supports pretty tree output (default) and JSON output (`--json`).
- Safe timeouts and graceful error handling.

## Usage

```bash
python spectrum.py domains.txt
python spectrum.py domains.txt --json
python spectrum.py domains.txt --no-cve
python spectrum.py domains.txt --max-cves 20
```

### domains.txt example

```text
example.com
https://portal.example.org
subdomain.yourcompany.com
```

## Notes

- Only scan domains you own or are explicitly authorized to test.
- CVE mapping is best-effort and based on product-level identifiers, not exact versions.
