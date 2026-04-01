# Origin IP AutoDetect

Burp Suite extension to detect origin IP exposure behind CDNs and WAFs using passive analysis and active probing.

---

## Overview

Origin IP AutoDetect helps identify backend server IPs that are unintentionally exposed behind CDNs, reverse proxies, or WAFs.  

It analyzes live traffic and performs intelligent probing to correlate responses and determine whether an IP likely serves the same content as the target host.

---

## Features

- Passive traffic analysis from Proxy and HTTP history  
- Active probing of resolved IP candidates  
- Response similarity scoring (status, body, headers, redirects)  
- Multi-sample correlation per host  
- Detection of WAF/CDN blocking behavior  
- Noise filtering for common third-party domains  
- Clear classification:
  - CONFIRMED_ORIGIN  
  - LIKELY_ORIGIN  
  - POSSIBLE_ORIGIN  
  - INCONCLUSIVE  
  - RESPONDS_BUT_BLOCKED  

---

## How It Works

1. Captures HTTP responses from Burp Proxy or history  
2. Extracts host and resolves candidate IPs  
3. Sends crafted requests directly to IPs  
4. Compares responses using:
   - Status codes  
   - Content similarity  
   - Headers and redirects  
5. Assigns a confidence score and classification  

---

## Usage

1. Load the extension in Burp Suite (Extender → Extensions)  
2. Browse target applications through Burp Proxy  
3. View results in the **OriginIpAutoDetect** tab  
4. Optionally:
   - Import HTTP history  
   - Import Site Map targets  
   - Enable/disable active probing  

---

## Requirements

- Burp Suite  
- Jython (for Python extensions)

---

## Notes

- Results are heuristic-based and may require manual validation  
- Some targets may block direct IP access (WAF/CDN protection)  
- Best results are obtained with multiple requests per host  

---

## Disclaimer

This tool is intended for authorized security testing and research purposes only.

---

## License

MIT License
