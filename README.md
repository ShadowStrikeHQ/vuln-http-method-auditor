# vuln-HTTP-Method-Auditor
Audits a website's allowed HTTP methods for each endpoint, highlighting potential vulnerabilities arising from allowing unintended methods like PUT, DELETE, or TRACE. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-http-method-auditor`

## Usage
`./vuln-http-method-auditor [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: The target URL to audit.
- `-e`: Specific endpoints to test. If not provided, attempts to test all discovered endpoints.
- `-m`: No description provided
- `-o`: No description provided
- `--discover`: Attempt to discover endpoints by crawling.
- `--user-agent`: Custom User-Agent string.
- `--timeout`: Request timeout in seconds.
- `--ignore-ssl`: Ignore SSL certificate validation errors.

## License
Copyright (c) ShadowStrikeHQ
