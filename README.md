# aggrescan.py

##  API Aggregation script to scan URLs / IPs / email addresses for malicious indicators

Created by Daniel Casey

---
### Current Version: *0.5*
### Features
 - Loads any configured API keys from *apis.txt* file in working directory
 - Scans URLs or IPs (email address scanning functionality not yet implemented)
 - Detects type of scan (URL / IP) automatically
 - Generates summary of completed scans in report format

### Integrated APIs
| API | Scan Type | API Limit(s) |
|--|--|--|
|[AbuseIPDB.com](https://docs.abuseipdb.com/#introduction) | IP | 1000 scans/day
|[Fraudguard.io](https://docs.fraudguard.io/)|IP| 1000 scans/month |
|[Google Safe Browsing](https://developers.google.com/safe-browsing/v4/lookup-api)| URL | ? |
|[Polyswarm.network](https://docs.polyswarm.io/consumers) | URL / IP | 250 scans/day |
|[Promptapi.com](https://promptapi.com/marketplace/description/whois-api#documentation-tab) (Whois)| URL | 100 scans/day |
|[Threatminer.org](https://www.threatminer.org/api.php)|URL / IP|?|
|[Urlscan.io](https://urlscan.io/docs/api/)|URL / Email Address| 100 unlisted scans/hr, 1000/day|
|[Virustotal.com](https://developers.virustotal.com/reference/overview)|URL|2 scans/min, 500/day|

*[Useful list of other tools / APIs](https://zeltser.com/lookup-malicious-websites/)*

___

### Installation

___

### Usage

___
