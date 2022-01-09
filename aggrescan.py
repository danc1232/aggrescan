# AGGRESCAN.PY - Daniel Casey
# https://github.com/danc1232/aggrescan

# API Aggregation script to scan URLs, IPs, and email addresses for malicious indicators
# v0.7.0

# standard packages
import json
import time
import os
import re
import argparse
import socket
import logging

# installed packages
import requests
from requests.auth import HTTPBasicAuth
from requests.models import PreparedRequest
import requests.exceptions
from polyswarm_api.api import PolyswarmAPI
from colorama import Fore, Style
from bs4 import BeautifulSoup
from requests_html import HTMLSession

# API request wrappers / output generation

def urlscan(url):
    if not API_KEYS['urlscan']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Urlscan.io{c.RES}')
    headers = {'API-Key':API_KEYS["urlscan"],'Content-Type':'application/json'}
    data = {"url": url, "visibility": "unlisted"}
    response = requests.post('https://urlscan.io/api/v1/scan',headers=headers, data=json.dumps(data))
    resp = response.json()
    if resp['message'] == 'Submission successful':
        UUID = resp['uuid']
    else:
        print(f"[{c.RED}#{c.RES}]\turlscan submission failed.")
        return False

    #   note, wait 10 seconds before polling result, then try every 2 seconds (minimum) with an upper limit of requests
    time.sleep(10)
    finished = False
    TIMEOUT_LIMIT = 5
    while not finished:
        if TIMEOUT_LIMIT < 0:
            print(f"[{c.YELLOW}#{c.RES}]\turlscan timed out.")
            return False
        result = requests.get('https://urlscan.io/api/v1/result/' + UUID)
        # json returned only includes status (of 404) when scan is incomplete
        if 'status' in result.json():
            print(f"[{c.GRAY}#{c.RES}]\t...")
            TIMEOUT_LIMIT -= 1
            time.sleep(4)
        else:
            finished = True

    res = result.json()
    t = res['task']
    p = res['page']
    l = res['lists']
    v = res['verdicts']

    verdict = v['overall']['score']

    if verdict == 0:
        verdict_color = c.GREEN
    elif verdict <= 50:
        verdict_color = c.YELLOW
    else:
        verdict_color = c.RED
    score = f"{verdict_color}{str(verdict)}{c.RES}"

    if 'url' in t: print(f"[{c.CYAN}#{c.RES}]\tURL Scanned:\t\t{c.CYAN}{t['url']}{c.RES}")
    if 'url' in p: print(f"[{c.CYAN}#{c.RES}]\tEffective URL:\t\t{c.CYAN}{p['url']}{c.RES}")
    if 'domain' in p: print(f"[{c.CYAN}#{c.RES}]\tResolved Hostname:\t{c.CYAN}{p['domain']}{c.RES}")
    if 'ip' in p: print(f"[{c.CYAN}#{c.RES}]\tPrimary Request IP:\t{c.CYAN}{p['ip']}{c.RES}")
    if 'country' in p: print(f"[{c.CYAN}#{c.RES}]\tCountry Code:\t\t{c.CYAN}{p['country']}{c.RES}")
    if 'city' in p and p['city']: print(f"[{c.CYAN}#{c.RES}]\tCity:\t\t\t{c.CYAN}{p['city']}{c.RES}")
    if 'server' in p: print(f"[{c.CYAN}#{c.RES}]\tServer:\t\t\t{c.CYAN}{p['server']}{c.RES}")
    if 'certificates' in l: cert = l['certificates'][0] if l['certificates'] else False
    if cert:
        ## parse validity timestamps
        issue_date = time.strftime("%a, %d %b %Y", time.gmtime(cert['validFrom'])) if 'validFrom' in cert else False
        valid_until = time.strftime("%a, %d %b %Y", time.gmtime(cert['validTo'])) if 'validTo' in cert else False

        if 'subjectName' in cert: print(f"[{c.CYAN}#{c.RES}]\tCert Subject Name:\t{c.CYAN}{cert['subjectName']}{c.RES}")
        if 'issuer' in cert: print(f"[{c.CYAN}#{c.RES}]\tCert Issuer:\t\t{c.CYAN}{cert['issuer']}{c.RES}")
        if issue_date: print(f"[{c.CYAN}#{c.RES}]\tIssue Date:\t\t{c.CYAN}{issue_date}{c.RES}")
        if valid_until: print(f"[{c.CYAN}#{c.RES}]\tValid Unitl:\t\t{c.CYAN}{valid_until}{c.RES}")
    else:
        print(f"[{c.YELLOW}#{c.RES}]\tNo TLS Certificate found.{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tScreenshot:\t\t{c.CYAN}https://urlscan.io/screenshots/{UUID}.png{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tThreat Category:\t{c.CYAN}{v['urlscan']['categories']}{c.RES}")
    print(f"[{verdict_color}#{c.RES}]\tVerdict:\t\t{score}")
    return res

    #   also screenshot can be found at https://urlscan.io/screenshots/$uuid.png
    #   things to pull from result

def fraud_guard(ip):
    if not API_KEYS['fraud-guard']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Fraudguard.io{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    addr = f'https://api.fraudguard.io/ip/{ip}'
    creds = API_KEYS['fraud-guard'].split('|')
    resp = requests.get(addr, verify=True, auth=HTTPBasicAuth(creds[0],creds[1]))
    r = resp.json()
    if 'country' in r: print(f"[{c.CYAN}#{c.RES}]\tCountry:\t\t{c.CYAN}{r['country']}{c.RES}")
    if 'threat' in r: print(f"[{c.CYAN}#{c.RES}]\tThreat:\t\t\t{c.CYAN}{r['threat']}{c.RES}")
    if 'risk_level' in r: print(f"[{c.CYAN}#{c.RES}]\tRisk Level:\t\t{c.CYAN}{r['risk_level']}{c.RES}")
    return r

def polyswarm(url):
    if not API_KEYS['polyswarm']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Polyswarm{c.RES}')
    api_key = API_KEYS['polyswarm']
    api = PolyswarmAPI(key=api_key)

    positives = 0
    total = 0
    instance = api.submit(url, artifact_type='url')
    result = api.wait_for(instance)

    if result.failed:
        print(f'[{c.RED}#{c.RES}]\tPolyswarm scan{c.RED}failed{c.RES}')
        return False
    ## default output
    """
    for assertion in result.assertions:
        if assertion.verdict:
            positives += 1
        total += 1
        judgement = 'Malicious' if assertion.verdict else 'Benign'
        print(f'\tEngine {assertion.author_name} asserts {judgement}')
    print(f'Positives: {positives}')
    print(f'Total: {total}\n') """

    ## custom output
    for assertion in result.assertions:
        if assertion.verdict:
            positives += 1
        total += 1
    perc = positives / total
    if perc == 0:
        hits_color = c.GREEN
    elif perc <= 0.5:
        hits_color = c.YELLOW
    else:
        hits_color = c.RED

    print(f'[{hits_color}#{c.RES}]\t{hits_color}{positives}/{total} hits.{c.RES}')

    return result

def virus_total(url):
    if not API_KEYS['virustotal']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Virus Total{c.RES} scanning:\t{c.CYAN}{url}{c.RES}')
    addr = 'https://www.virustotal.com/api/v3/urls'
    payload = {"url": url}
    headers = { "Accept": "application/json","x-apikey": API_KEYS['virustotal'],"Content-Type": "application/x-www-form-urlencoded" }

    response = requests.post(addr, data=payload, headers=headers)
    if response.status_code == 200:
        ID = response.json()['data']['id']
    else:
        print(f'[{c.RED}#{c.RES}]\tVirus Total scan{c.RED}failed{c.RES}')
        return False

    addr = f'https://www.virustotal.com/api/v3/analyses/{ID}'
    headers = { "Accept": "application/json", "x-apikey": API_KEYS['virustotal'] }
    TIMEOUTS = 4
    while True:
        if TIMEOUTS < 0:
            print(f'[{c.RED}#{c.RES}]\tVirus Total scan{c.RED} timed out{c.RES}')
            return False
        response = requests.get(addr, headers=headers)
        r = response.json()
        if r['data']['attributes']['status'] == 'completed':
            break
        TIMEOUTS -= 1
        time.sleep(10)

    stats = r['data']['attributes']['stats']
    h = stats['harmless']
    m = stats['malicious']
    s = stats['suspicious']
    u = stats['undetected']
    t = stats['timeout']
    total = h+m+s+u+t
    if h > 0: print(f'[{c.GREEN}#{c.RES}]\t{c.GREEN}{h}{c.RES}/{total}\t\t\t{c.GREEN}harmless{c.RES}')
    if u > 0: print(f'[{c.CYAN}#{c.RES}]\t{c.CYAN}{u}{c.RES}/{total}\t\t\t{c.CYAN}undetected{c.RES}')
    if t > 0: print(f'[{c.GRAY}#{c.RES}]\t{c.GRAY}{t}{c.RES}/{total}\t\t\t{c.GRAY}timeout{c.RES}')
    if s > 0: print(f'[{c.YELLOW}#{c.RES}]\t{c.YELLOW}{s}{c.RES}/{total}\t\t\t{c.YELLOW}suspicious{c.RES}')
    if m > 0: print(f'[{c.RED}#{c.RES}]\t{c.RED}{m}{c.RES}/{total}\t\t\t{c.RED}malicious{c.RES}')

def threat_miner_url(url,isRetry):
    url = strip_canon(url).split('/')[0]
    if isRetry:
        print(f'[{c.GRAY}###{c.RES}]\t{c.GRAY}Retrying root domain:{c.RES}\t{c.CYAN}{url}{c.RES}')
    else:
        print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Threat Miner{c.RES} scanning:\t{c.CYAN}{url}{c.RES}')
    ## todo: if scanning subdomain, re-scan for root domain info before displaying results
    addr = f"https://api.threatminer.org/v2/domain.php?q={url}"
    headers = { "Accept": "application/json" }
    response = requests.get(addr, headers=headers)
    r = response.json()
    status = int(r['status_code'])
    if status != 200:
        if status == 404:
            if not isRetry:
                print(f'[{c.YELLOW}#{c.RES}]\tThreat Miner could not find registration info.')
                threat_miner_url(get_domain(url),True)
            else:
                print(f'[{c.YELLOW}#{c.RES}]\tRegistration info still not found.')
        else:
            print(f'[{c.RED}#{c.RES}]\tThreat Miner scan {c.RED}failed{c.RES}')
        return False

    r = r['results'][0]
    w = r['whois'] if ('whois' in r) else {}
    i = w['registrant_info'] if ('registrant_info' in w) else {}

    print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t{c.CYAN}{r['domain']}.{c.RES}")
    if 'is_subdomain' in r and r['is_subdomain']:
        if 'root_domain' in r: print(f"[{c.CYAN}#{c.RES}]\tRoot Domain:\t\t{c.CYAN}{r['root_domain']}.{c.RES}")
    if w:
        if 'creation_date' in w:
            # parse date, sometimes it's given in seconds instead of a normal date
            c_date = time.strftime("%a, %d %b %Y", time.gmtime(w['creation_date']['sec'])) if 'sec' in w['creation_date'] else w['creation_date']
            print(f"[{c.CYAN}#{c.RES}]\tDomain Creation Date:\t{c.CYAN}{c_date}.{c.RES}")
        if 'registrar' in w: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{w['registrar']}{c.RES}")
    if i:
        if 'Country' in i: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Country:\t{c.CYAN}{i['Country']}{c.RES}")
        if 'Organization' in i: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Org:\t\t{c.CYAN}{i['Organization']}{c.RES}")

def threat_miner_ip(ip):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Threat Miner{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    ## todo: if scanning subdomain, re-scan for root domain info before displaying results?
    addr = f"https://api.threatminer.org/v2/host.php?q={ip}"
    headers = { "Accept": "application/json" }
    response = requests.get(addr, headers=headers)
    r = response.json()
    status = int(r['status_code'])
    if status != 200:
        if status == 404:
            print(f'[{c.YELLOW}#{c.RES}]\tThreat Miner could not find registration info.')
        else:
            print(f'[{c.RED}#{c.RES}]\tThreat Miner scan {c.RED}failed{c.RES}')
        return False
    r = r['results'][0]

    if 'cc' in r: print(f"[{c.CYAN}#{c.RES}]\tCountry Code:\t\t{c.CYAN}{r['cc']}{c.RES}")
    if 'org_name' in r: print(f"[{c.CYAN}#{c.RES}]\tOrganization:\t\t{c.CYAN}{r['org_name']}{c.RES}")
    if 'register' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['register']}{c.RES}")

def prompt_whois(url):
    # seems like this can only scan root domains, so convert any urls to that first
    if not API_KEYS['prompt-whois']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Promptapi WHOIS{c.RES}')
    url = get_domain(url)
    addr = f"https://api.promptapi.com/whois/query?domain={url}"
    headers= {"apikey": API_KEYS['prompt-whois']}
    response = requests.get(addr, headers=headers)
    status = response.status_code
    if status != 200:
        if status == 404:
            print(f'[{c.YELLOW}#{c.RES}]\tPromptapi could not find registration info.')
        elif status == 429:
            print(f'[{c.YELLOW}#{c.RES}]\tExceeded daily API request limit.')
        else:
            print(f'[{c.RED}#{c.RES}]\tPromptapi scan failed: {response.json()["message"]}')
        return False
    r = response.json()['result']

    if 'domain_name' in r: print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t{c.CYAN}{r['domain_name']}.{c.RES}")
    if 'creation_date' in r: print(f"[{c.CYAN}#{c.RES}]\tDomain Creation Date:\t{c.CYAN}{r['creation_date']}.{c.RES}")
    if 'registrar' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['registrar']}{c.RES}")
    if 'country' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Country:\t{c.CYAN}{r['country']}{c.RES}")
    if 'org' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Org:\t\t{c.CYAN}{r['org']}{c.RES}")

def abuseipdb(ip):
    if not API_KEYS['abuseipdb']: return False
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}AbuseIPDB{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    cats = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Email Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"}

    endpoint = 'https://api.abuseipdb.com/api/v2/check'
    headers= {
        'Accept': 'application/json',
        'Key': f"{API_KEYS['abuseipdb']}"
        }
    query = {'ipAddress': ip,'verbose': True}

    response = requests.get(endpoint, headers=headers, params=query)

    status = response.status_code
    if status != 200:
        print(f'[{c.RED}#{c.RES}]\tAbuseIPDB scan failed:')
        for err in response.json()['errors']:
            print(f'[{c.RED}#{c.RES}]\tStatus: {err["status"]}\tError: {err["detail"]}')
        return False
    r = response.json()['data']

    total_reports = r['totalReports'] if 'totalReports' in r else False

    if 'abuseConfidenceScore' in r:
        acs = r['abuseConfidenceScore']
        if acs == 0:
            acs_color = c.GREEN
        elif acs < 50:
            acs_color = c.YELLOW
        else:
            acs_color = c.RED
    else:
        acs = False
        acs_color = ""

    if 'countryName' in r: print(f"[{c.CYAN}#{c.RES}]\tCountry:\t\t{c.CYAN}{r['countryName']}{c.RES}")
    if 'usageType' in r: print(f"[{c.CYAN}#{c.RES}]\tUsage Type:\t\t{c.CYAN}{r['usageType']}{c.RES}")
    if 'isp' in r: print(f"[{c.CYAN}#{c.RES}]\tISP:\t\t\t{c.CYAN}{r['isp']}.{c.RES}")
    if 'domain' in r: print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t{c.CYAN}{r['domain']}{c.RES}")
    if total_reports: print(f"[{acs_color}#{c.RES}]\tTotal Reports:\t\t{acs_color}{str(total_reports)}{c.RES}")
    if acs: print(f"[{acs_color}#{c.RES}]\tAbuse Confidence Score:\t{acs_color}{acs}{c.RES}")

    ## if reports are found, display info from the most recent report
    if total_reports > 0:
        last_report = r['reports'][0]
        report_date = last_report['reportedAt']
        categoryList = ""
        for cat in last_report['categories']:
            categoryList += f'{cats[cat]}, '
        categoryList = categoryList.rstrip(', ')
        print(f"[{c.GRAY}>>{c.RES}]\tMost Recent Report:")
        # these comments can be messy
        # print(f"[{c.CYAN}#{c.RES}]\tComment:\t\t\t{c.CYAN}{last_report['comment']}.{c.RES}")
        print(f"[{c.CYAN}#{c.RES}]\tReport Date:\t\t{c.CYAN}{report_date}{c.RES}")
        print(f"[{c.YELLOW}#{c.RES}]\tCategories:\t\t{c.YELLOW}{categoryList}{c.RES}")

def google_safe_browse(url):
    if not API_KEYS['google-safe-browse']: return False
    # doesn't flag malicious sites that it's own sister utility (the manual submission transparency report utility) flags
    # according to the issue trackers / bug reports I've read (some beginning in 2015...) not a lot of progress will be made on that front
    # not perfect but sometimes it works!
    url = canonicalize(url,True)
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}GSB Lookup API:{c.RES}\t{c.CYAN}{url}{c.RES}')


    payload = {
        "client": {"clientId": "aggrescan", "clientVersion": "0.5"},
        'threatInfo': {"threatTypes": [
                            "SOCIAL_ENGINEERING",
                            "MALWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                            "UNWANTED_SOFTWARE",
                            "THREAT_TYPE_UNSPECIFIED"
                            ],
                       'platformTypes': ["ANY_PLATFORM"],
                       'threatEntryTypes': ["URL"],
                       'threatEntries': [{"url": f'https://{url}'}]}}
    addr = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEYS['google-safe-browse']}"

    response = requests.post(addr, json=payload)
    # api get request to show available lists and threat platforms / types
    #response = requests.get(f"https://safebrowsing.googleapis.com/v4/threatLists?key={API_KEYS['google-safe-browse']}",headers=headers)
    r = response.json()
    if 'matches' in r:
        for match in r['matches']:
            flag = match['threatType']
            print(f"[{c.RED}#{c.RES}]\tFlagged for: {c.RED}{flag}{c.RES}")
    else:
        print(f"[{c.CYAN}#{c.RES}]\tNo hits")

    return True

# Scraping functions (manually access non-API resources)

def google_sb_scrape(url):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}GSB Site Report:{c.RES} {c.CYAN}{url}{c.RES}')
    url = strip_canon(url)
    session = HTMLSession()
    addr = f'https://transparencyreport.google.com/safe-browsing/search?url={url}'
    try:
        r = session.get(addr)
        r.html.render(timeout=20)
        session.close()
    except:
        print(f"[{c.YELLOW}#{c.RES}]\tGSB Site Report timed out.")
        return False

    soup = BeautifulSoup(r.html.html, "html.parser")
    value = soup.find('span', {"aria-label":'figure value'})

    if value.text == "This site is unsafe":
        print(f"[{c.RED}#{c.RES}]\t{c.RED}Unsafe content detected!{c.RES}")
    elif value.text == "Some pages on this site are unsafe":
        print(f"[{c.YELLOW}#{c.RES}]\t{c.YELLOW}Some unsafe content detected!{c.RES}")
    elif value.text == "No unsafe content found":
        print(f"[{c.GREEN}#{c.RES}]\t{c.GREEN}No unsafe content found.{c.RES}")
    elif value.text == "Check a specific URL":
        print(f"[{c.GRAY}X{c.RES}]\tNon-specific URL provided.")
    else:
         print(f"[{c.GRAY}?{c.RES}]\t{value.text}")

# Utilities

# color helper defs, can be reset to empty strings for colorblind-friendly output
class c:
    MAG = Fore.MAGENTA
    CYAN = Fore.CYAN
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    GRAY = Fore.WHITE
    RES = Style.RESET_ALL

def colorblind():
    c.BLUE = ""
    c.CYAN = ""
    c.BLUE = ""
    c.GREEN = ""
    c.YELLOW = ""
    c.RED = ""
    c.GRAY = ""
    c.RES = ""

# cross-platform clear terminal command
def clear():
    os.system('cls||clear')

# if link is not http or https, add http/s
def canonicalize(url,s):
    if not re.match('(?:http|https)://', url):
        if s:
            return 'https://{}'.format(url)
        else:
            return 'http://{}'.format(url)
    return url

# if link starts with http or https, remove it
def strip_canon(url):
    url = re.sub('(?:http|https)://','',url).strip()
    return url

# API helper function to load keys from ./.apis text file
def load_api_keys():
    # structure: {"APINAME": "KEY")} -- if api is not configured, tuple is left as False
    global API_KEYS
    API_KEYS = {
    "urlscan": False,
    "google-safe-browse": False,
    "fraud-guard": False,
    "polyswarm": False,
    "virustotal": False,
    "prompt-whois": False,
    "abuseipdb": False
    }

    try:
    # load keys from .apis file in src directory
        with open('apis.txt') as f:
            lines = f.readlines()
        for line in lines:
            line = line.split()
            if line[0] == '#':
                continue
            if line[0] in API_KEYS:
                API_KEYS[line[0]] = line[1]
    except IOError as err:
        print("Error loading apis: " + err)

    none_found = True
    for config in API_KEYS:
        if API_KEYS[config]:
            print(f"[{c.CYAN}#{c.RES}]\tsuccessfully loaded {c.GREEN}{config}{c.RES} key.")
            time.sleep(0.2)
            none_found = False
    if none_found:
        print(f"[{c.RED}#{c.RES}]\tNo API keys loaded. Functionality will be limited.")
    time.sleep(2)

# parse command line arguments
def parse_args():
    # Parse command line arguments
    desc = f'{c.BLUE}Aggrescan.py{c.RES} - Daniel Casey\nVersion {c.CYAN}0.7.0{c.RES}\n{c.GRAY}Scan URLS / IPs / Email addresses for malicious indicators{c.RES}\n'

    parser = argparse.ArgumentParser(description=desc,allow_abbrev=False,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', type=str, help="The URL/IP to scan")
    # haven't implemented verbosity yet in messages
    parser.add_argument('-v', '--verbose', action="store_true", help="display verbose output")
    parser.add_argument('-q', '--quiet', action="store_true", help="remove color formatting from output")
    args = parser.parse_args()
    return args

# parse target string to identify whether it is Email, IP, or URL
def parse_target(target):
    ip_regex = re.compile(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')
    email_regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    url_regex = re.compile(r'(http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?')
    if re.fullmatch(ip_regex,target):
        return("ip")
    elif re.fullmatch(email_regex,target):
        return("email")
    elif re.fullmatch(url_regex,canonicalize(target,False)):
        if url_is_valid(target):
            return("url")
    else:
        return False

# utility to check if url is valid
def url_is_valid(url):
    canon = canonicalize(url,False)
    prepared_request = PreparedRequest()
    try:
        prepared_request.prepare_url(canon, None)
    except requests.exceptions.MissingSchema as e:
        return False
    return True

# wrapper for socket.gethostbyname() function
# if IP can't be resolved return false
def resolve_host(url):
    try:
        ip = socket.gethostbyname(strip_canon(url))
        return ip
    except socket.gaierror as err:
        return False

# try to parse out domain (NOT PERFECT)
# for ex. bbc.co.uk will break this
# need to add -f, --force for option to explicitly scan url / ip
# and warning to users to use -f if scans aren't working as desired
def get_domain(url):
    url = strip_canon(url).split('/')[0]
    tokens = url.split('.')
    url = f'{tokens[-2]}.{tokens[-1]}'
    return url

# Main Loop
def main():
    ## clean up all the noise generated by logs
    logging.root.setLevel(logging.WARNING)
    clear()
    try:
        args = parse_args()
        if args.quiet:
            colorblind()
        print(f'[{c.GREEN}>>>{c.RES}]\t{c.GRAY}Welcome to{c.RES} {c.GREEN}Aggrescan{c.RES}')
        load_api_keys()
        if not args.verbose: clear()
        target_type = parse_target(args.target.strip())
        if not target_type:
            print(f'[{c.RED}X{c.RES}]\tUnable to determine target type. Make sure target is a valid URL or IP address.')
        else:
            if target_type == "email":
                print(f'[{c.RED}X{c.RES}]\tEmail address scan not yet implemented.')
            else:
                if target_type == "ip":
                    ip = args.target
                    print(f'[{c.GREEN}>>>{c.RES}]\tAggrescan report for IP: {c.BLUE}{ip}{c.RES}')
                    threat_miner_ip(ip)
                    fraud_guard(ip)
                    abuseipdb(ip)
                    urlscan(canonicalize(ip,False))
                elif target_type == "url":
                    url = canonicalize(args.target,True)
                    print(f'[{c.GREEN}>>>{c.RES}]\tAggrescan report for URL: {c.BLUE}{url}{c.RES}')
                    ip = resolve_host(url)
                    u = urlscan(url)
                    # try to resolve IP with socket, if that doesn't work and URL scan configured, use that
                    # otherwise, don't run IP scans
                    if ip:
                        if args.verbose: print(f'[{c.GRAY}#{c.RES}]\tIP resolved to: {c.BLUE}{ip}{c.RES}')
                        pass
                    else:
                        if u: ip = u['page']['ip']
                        # ip still not resolved, warn users
                        if not ip:
                            print(f'[{c.RED}X{c.RES}]\tIP not resolved (try root domain scan or without subdirectory?)')
                            print(f'[{c.RED}X{c.RES}]\tSkipping IP scans')
                    threat_miner_url(url,False)
                    prompt_whois(url)
                    google_safe_browse(url)
                    google_sb_scrape(url)
                    polyswarm(url)
                    virus_total(url)
                    if ip:
                        fraud_guard(ip)
                        abuseipdb(ip)
    except KeyboardInterrupt as e:
        print(f'[{c.GRAY}X{c.RES}]\tManually exiting Aggrescan. {c.BLUE}Goodbye.{c.RES}')

main()
