# Origin IP AutoDetect

Burp Suite extension to detect origin IP exposure behind CDNs and WAFs using passive analysis and active probing.

---

## Features

- Passive traffic analysis (Proxy + HTTP history)
- Active probing of resolved IPs
- Response similarity scoring
- Multi-request correlation per host
- Detection of WAF/CDN blocking
- Noise filtering for common third-party domains

---

## How It Works

1. Captures HTTP responses from Burp
2. Resolves candidate IPs for each host
3. Sends requests directly to those IPs
4. Compares responses (status, body, headers, redirects)
5. Assigns score and classification

---

## Scoring

Each probe is scored (0–100) based on response similarity:
- Status code
- Content similarity
- Headers and redirects
- Response length

Scores are averaged across multiple requests.

**Matches:** responses with score ≥ 75  
Displayed as: `strong_matches / total_responses`

---

## Results

- **CONFIRMED_ORIGIN**
- **LIKELY_ORIGIN**
- **POSSIBLE_ORIGIN**
- **INCONCLUSIVE**
- **RESPONDS_BUT_BLOCKED**

---

## Usage

1. Load extension in Burp
2. Browse target via Proxy
3. Open **OriginIpAutoDetect** tab
4. (Optional) Import HTTP history or Site Map

---

## Requirements

- Burp Suite
- Jython

---

## License

MIT License

---

## Author

Raghav Vivekanandan @ Ashtaksha Labs
