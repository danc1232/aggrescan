# AGGRESCAN.PY - Daniel Casey
# Scan URLs / IPs / Email Addresses for malicious indicators

# v0.5
# Currently scans URLs or IPs (Email Address scanning functionality not yet implemented)
# Detects type of scan (URL / IP) automatically

# Integrated APIs
### urlscan.io          = query url or email address | https://urlscan.io/docs/api/
### googlesafebrowse    = checks URL against google safebrowsing lists | 
### fraudguard.io       = IP scan, 1000 checks / month | https://docs.fraudguard.io/
### polyswarm.network   = 250 daily IP / hostname checks | https://docs.polyswarm.io/consumers
### virustotal.com      = robust URL scan | https://developers.virustotal.com/reference/overview
### threatminer.org     = WHOIS info with free api | https://www.threatminer.org/api.php
### promptapi - whois   = WHOIS api with 100 daily lookups | https://promptapi.com/marketplace/description/whois-api#documentation-tab
### abuseipdb.com       = IP Scan, 1000 checks / day | https://docs.abuseipdb.com/#introduction

# Useful list of other tools / APIs: https://zeltser.com/lookup-malicious-websites/

# standard packages
import json
import time
import os
import re
import argparse
import socket

# installed packages
import requests
from requests.auth import HTTPBasicAuth
from requests.models import PreparedRequest
import requests.exceptions
from polyswarm_api.api import PolyswarmAPI
from colorama import Fore, Style

# API requests

def urlscan(url):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Urlscan.io{c.RES}')
    # these are straight out of docs
    headers = {'API-Key':API_KEYS["urlscan"],'Content-Type':'application/json'}
    data = {"url": url, "visibility": "unlisted"}
    response = requests.post('https://urlscan.io/api/v1/scan',headers=headers, data=json.dumps(data))
    # successful response will include dict with values:
    #   'message': 'Submission successful',
    #   'uuid': UUID,
    #   'result': link/to/result,
    #   'api': link/to/api/result,
    #   etc..
    #   the result can be queried further with the result with uuid
    #   new response object ->
    #   response = requests.post('https://urlscan.io/api/v1/result/$UUID)
    #   this response will return a 404 until the scan is finished, at which point it will return a 200
    #   with a new result JSON object
    resp = response.json()
    if resp['message'] == 'Submission successful':
        UUID = resp['uuid']
    else:
        print(f"[{c.RED}#{c.RES}]\turlscan submission failed.")
        return False

    #   note, wait 10 seconds before polling result, then try every 2 seconds with an upper limit of requests
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
    verdict = res['verdicts']['urlscan']['score']
    pref = f""
    if verdict == 0:
        pref = f"{c.GREEN}"
    elif verdict <= 50:
        pref = f"{c.YELLOW}"
    else:
        pref = f"{c.RED}"
    score = pref + f"{str(verdict)}{c.RES}"

    print(f"[{c.GREEN}#{c.RES}]\tURL Scanned: {c.CYAN}{res['task']['url']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tResolved Hostname: {c.CYAN}{res['page']['domain']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tPrimary Request IP: {c.CYAN}{res['page']['ip']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tCountry Code: {c.CYAN}{res['page']['country']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tScreenshot: {c.CYAN}https://urlscan.io/screenshots/{UUID}.png{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tThreat Category: {c.CYAN}{res['verdicts']['urlscan']['categories']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tURLScan Verdict: {score}")

    return res

    #   also screenshot can be found at https://urlscan.io/screenshots/$uuid.png
    #   things to pull from result

def fraud_guard(ip):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Fraudguard.io{c.RES}')
    print(f'[{c.CYAN}#{c.RES}]\tScanning IP: {c.CYAN}{ip}{c.RES}')
    addr = f'https://api.fraudguard.io/ip/{ip}'
    creds = API_KEYS['fraud-guard'].split('|')
    resp = requests.get(addr, verify=True, auth=HTTPBasicAuth(creds[0],creds[1]))
    r = resp.json()
    print(f"[{c.GREEN}#{c.RES}]\tCountry: {c.CYAN}{r['country']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tThreat: {c.CYAN}{r['threat']}{c.RES}")
    print(f"[{c.GREEN}#{c.RES}]\tRisk Level: {c.CYAN}{r['risk_level']}{c.RES}")
    
    return r

def polyswarm(url):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Polyswarm{c.RES}')
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
        indicator = f'{c.GREEN}'
    elif perc <= 0.5:
        indicator = f'{c.YELLOW}'
    else:
        indicator = f'{c.RED}'

    print(f'[{indicator}#{c.RES}]\t{indicator}{positives}/{total} hits.{c.RES}')
    
    return result

def virus_total(url):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Virus Total{c.RES}')
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
    print(f'[{c.GREEN}#{c.RES}]\t{h}/{total} {c.GREEN}harmless{c.RES}')
    print(f'[{c.CYAN}#{c.RES}]\t{u}/{total} {c.CYAN}undetected{c.RES}')
    print(f'[{c.GRAY}#{c.RES}]\t{t}/{total} {c.GRAY}timeout{c.RES}')
    print(f'[{c.YELLOW}#{c.RES}]\t{s}/{total} {c.YELLOW}suspicious{c.RES}')
    print(f'[{c.RED}#{c.RES}]\t{m}/{total} {c.RED}malicious{c.RES}')

def threat_miner_url(url):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Threat Miner (URL){c.RES}')
    ## todo: if scanning subdomain, re-scan for root domain info before displaying results
    url = strip_canon(url)
    addr = f"https://api.threatminer.org/v2/domain.php?q={url}"
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
    if 'whois' in r:
        w = r['whois']
    else:
        w = False
    if 'registrant_info' in w:
        i = w['registrant_info']
    else:
        i = False

    print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t {c.CYAN}{r['domain']}.{c.RES}")
    if 'is_subdomain' in r:
        if 'root_domain' in r: print(f"[{c.CYAN}#{c.RES}]\tRoot Domain:\t\t {c.CYAN}{r['root_domain']}.{c.RES}")
    if w:
        if 'creation_date' in w: print(f"[{c.CYAN}#{c.RES}]\tDomain Creation Date:\t {c.CYAN}{w['creation_date']}.{c.RES}")
        if 'registrar' in w: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t {c.CYAN}{w['registrar']}{c.RES}")
    if i: 
        if 'Country' in i: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Country:\t{c.CYAN}{i['Country']}{c.RES}")
        if 'Organization' in i: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Org:\t\t{c.CYAN}{i['Organization']}{c.RES}")

def threat_miner_ip(ip):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Threat Miner (IP){c.RES}')
    ## todo: if scanning subdomain, re-scan for root domain info before displaying results
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
    print(f"[{c.CYAN}#{c.RES}]\tCountry Code:\t\t{c.CYAN}{r['cc']}{c.RES}")
    if r['org_name']:
        print(f"[{c.CYAN}#{c.RES}]\tOrganization:\t\t{c.CYAN}{r['org_name']}{c.RES}")
    if r['register']:
        print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['register']}{c.RES}")

def prompt_whois(url):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Promptapi WHOIS{c.RES}')
    url = strip_canon(url)
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

    print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t{c.CYAN}{r['domain_name']}.{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tDomain Creation Date:\t{c.CYAN}{r['creation_date']}.{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['registrar']}{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tRegistrant Country:\t{c.CYAN}{r['country']}{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tRegistrant Org:\t\t{c.CYAN}{r['org']}{c.RES}")

def abuseipdb(ip):
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}AbuseIPDB{c.RES}')
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

    totalReports = r['totalReports']
    if totalReports == 0:
        totalRepColor = c.GREEN
    if totalReports > 0:
        totalRepColor = c.GRAY
    if totalReports >= 500:
        totalRepColor = c.YELLOW
    if totalReports >= 1000:
        totalRepColor = c.RED

    acs = r['abuseConfidenceScore']
    if acs == 0:
        acsColor = c.GREEN
    if acs > 0:
        acsColor = c.GRAY
    if acs > 50:
        acsColor = c.YELLOW
    if acs >= 75:
        acsColor = c.RED

    print(f"[{c.CYAN}#{c.RES}]\tCountry:\t\t\t{c.CYAN}{r['countryName']}{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tUsage Type:\t\t\t{c.CYAN}{r['usageType']}{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tISP:\t\t\t\t{c.CYAN}{r['isp']}.{c.RES}")
    print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t\t{c.CYAN}{r['domain']}{c.RES}")
    print(f"[{totalRepColor}#{c.RES}]\tTotal Reports:\t\t\t{totalRepColor}{str(totalReports)}{c.RES}")
    print(f"[{acsColor}#{c.RES}]\tAbuse Confidence Score:\t\t{acsColor}{acs}{c.RES}")
    if r['totalReports'] > 0:
        rep = r['reports'][0]
        repdate = rep['reportedAt']
        categoryList = ""
        for cat in rep['categories']:
            categoryList += f'{cats[cat]}, '
        categoryList = categoryList.rstrip(', ')
        print(f"[{c.YELLOW}>>{c.RES}]\tMost Recent Report:")
        #print(f"[{c.CYAN}#{c.RES}]\tComment:\t\t\t{c.CYAN}{rep['comment']}.{c.RES}")
        print(f"[{c.CYAN}#{c.RES}]\tReport Date:\t\t\t{c.CYAN}{repdate}{c.RES}")
        print(f"[{c.CYAN}#{c.RES}]\tCategories:\t\t\t{c.CYAN}{categoryList}{c.RES}")

def google_safe_browse(url):
    # doesn't flag malicious sites that it's own sister utility (the manual submission safe-browse checker tool) flags
    # not perfect but sometimes it works!
    print(f'[{c.MAG}###{c.RES}]\t{c.MAG}Google Safe Browsing{c.RES}')

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
    c.MAG = ""
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

# if link is not http or https, add http
def canonicalize(url):
    if not re.match('(?:http|https)://', url):
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
            print(f"[{c.GREEN}#{c.RES}]\tsuccessfully loaded {c.CYAN}{config}{c.RES} key.")
            none_found = False
    if none_found:
        print(f"[{c.RED}#{c.RES}]\tno API keys loaded. Exiting.")
        exit(1)

# parse command line arguments
def parse_args():
    # Parse command line arguments
    desc = f'{c.MAG}Aggrescan.py{c.RES} - Daniel Casey\nVersion {c.CYAN}0.5{c.RES}\n{c.GRAY}Scan URLS / IPs / Email addresses for malicious indicators{c.RES}\n'

    parser = argparse.ArgumentParser(description=desc,allow_abbrev=False,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', type=str, help="The URL/IP to scan")
    # haven't implemented verbosity yet in messages
    #parser.add_argument('-v', '--verbose', action="store_true", help="Verbose output")
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
    elif re.fullmatch(url_regex,canonicalize(target)):
        if url_is_valid(target):
            return("url")
    else:
        return False
    
# utility to check if url is valid
def url_is_valid(url):
    canon = canonicalize(url)
    prepared_request = PreparedRequest()
    try:
        prepared_request.prepare_url(canon, None)
    except requests.exceptions.MissingSchema as e:
        return False
    return True

# wrapper for socket.gethostbyname() function
def resolve_host(url):
    try:
        ip = socket.gethostbyname(strip_canon(url))
        return ip
    except socket.gaierror as err:
        return False

# Main Loop
def main():
    clear()
    args = parse_args()
    if args.quiet:
        colorblind()
    print(f'Welcome to {c.MAG}Aggrescan{c.RES}')
    load_api_keys()
    clear()
    target_type = parse_target(args.target.strip())
    if not target_type:
        print(f'[{c.RED}X{c.RES}]\tUnable to determine target type. Make sure target is a valid URL or IP address.')
    else:
        if target_type == "email":
            print(f'[{c.RED}X{c.RES}]\tEmail address scan not yet implemented.')
        else:
            if target_type == "ip":
                ip = args.target
                print(f'Aggrescan report for IP: {c.MAG}{ip}{c.RES}')
                threat_miner_ip(ip)
                fraud_guard(ip)
                abuseipdb(ip)
            elif target_type == "url":
                url = args.target
                print(f'Aggrescan report for URL: {c.MAG}{url}{c.RES}')
                ip = resolve_host(url)
                u = urlscan(url)
                if ip:
                    print(f'IP Resolved to: {c.MAG}{ip}{c.RES}')
                else:
                    ip = u['page']['ip']
                threat_miner_url(url)
                prompt_whois(url)
                google_safe_browse(url)
                polyswarm(url)
                virus_total(url)
                fraud_guard(ip)
                abuseipdb(ip)
        
main()