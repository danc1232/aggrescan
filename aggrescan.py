##############################################################################
#
#   __ _   __ _   __ _  _ __  ___  ___   ___  __ _  _ __      _ __   _   _
#  / _` | / _` | / _` || '__|/ _ \/ __| / __|/ _` || '_ \    | '_ \ | | | |
# | (_| || (_| || (_| || |  |  __/\__ \| (__| (_| || | | | _ | |_) || |_| |
#  \__,_| \__, | \__, ||_|   \___||___/ \___|\__,_||_| |_|(_)| .__/  \__, |
#          __/ |  __/ |                                      | |      __/ |
#         |___/  |___/                                       |_|     |___/
#
##############################################################################
# aggrescan.py - Daniel Casey
# https://github.com/danc1232/aggrescan

# API Aggregation script to scan URLs, IPs, and email addresses for malicious indicators
# v0.8.0

#####################   STANDARD PACKAGES   ######################
import json
import time
import os
import re
import argparse
import socket
import logging

####################   NONSTANDARD PACKAGES   ####################
import requests
from requests.auth import HTTPBasicAuth
from requests.models import PreparedRequest
import requests.exceptions
from polyswarm_api.api import PolyswarmAPI
from colorama import Fore, Style
from bs4 import BeautifulSoup
from requests_html import AsyncHTMLSession, HTMLSession
import asyncio
import aiohttp

############################   REQS   ############################

### URLSCAN ######################################################
async def urlscan_req(url):
    headers = {'API-Key':API_KEYS["urlscan"],'Content-Type':'application/json'}
    data = {"url": url, "visibility": "unlisted"}
    async with aiohttp.ClientSession() as session:
        async with session.post('https://urlscan.io/api/v1/scan',headers=headers, data=json.dumps(data)) as post_resp:
            pr = await post_resp.json()
            finished = False
            TIMEOUT_LIMIT = 5
            retries = 0
            if pr['message'] == 'Submission successful':
                UUID = pr['uuid']
            else:
                return ["failed", retries]
            await asyncio.sleep(6)
            while not finished:
                if TIMEOUT_LIMIT < 0:
                    return ["timeout", retries]
                async with session.get('https://urlscan.io/api/v1/result/' + UUID) as get_resp:
                    gr = await get_resp.json()
                    if 'status' in gr:
                        TIMEOUT_LIMIT -= 1
                        await asyncio.sleep(2)
                    else:
                        finished = True
            return [gr, retries]

async def urlscan_main(url):
    scan = await urlscan_req(url)
    urlscan_parse(url, scan[0], scan[1])
    return None

def urlscan_parse(url, resp, retries):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Urlscan.io:{c.RES}\t{c.CYAN}{url}{c.RES}')
    for i in range(retries):
        print(f"[{c.GRAY}#{c.RES}]\t...")
    if resp == "timeout":
        print(f"[{c.YELLOW}#{c.RES}]\tUrlscan timed out.")
    elif resp == "failed":
        print(f"[{c.RED}#{c.RES}]\tUrlscan submission failed.")
    elif resp:
        res = resp
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
        UUID = t['uuid']

        if 'url' in t: print(f"[{c.CYAN}#{c.RES}]\tURL Scanned:\t\t{c.CYAN}{t['url']}{c.RES}")
        if 'url' in p: print(f"[{c.CYAN}#{c.RES}]\tEffective URL:\t\t{c.CYAN}{p['url']}{c.RES}")
        if 'domain' in p: print(f"[{c.CYAN}#{c.RES}]\tResolved Hostname:\t{c.CYAN}{p['domain']}{c.RES}")
        if 'ip' in p: print(f"[{c.CYAN}#{c.RES}]\tPrimary Request IP:\t{c.CYAN}{p['ip']}{c.RES}")
        if 'country' in p: print(f"[{c.CYAN}#{c.RES}]\tCountry:\t\t{c.CYAN}{cc.codes[p['country']]}{c.RES}")
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
    else:
        print(f"[{c.RED}#{c.RES}]\turlscan submission failed.")
        return False

### THREATMINER (URL) ############################################
async def tm_url_main(url):
    scan = await tm_url_session_wrapper(url)
    tm_url_parse(url, scan[0], scan[1])
    return None

def tm_url_parse(url, json, wasRetry):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Threat Miner{c.RES} scanning:\t{c.CYAN}{url}{c.RES}')
    r = json
    if wasRetry:
        print(f'[{c.YELLOW}#{c.RES}]\tThreat Miner could not find registration info.')
        print(f'[{c.GRAY}>>{c.RES}]\t{c.GRAY}Retrying root domain...{c.RES}')
    status = int(r['status_code'])
    if status != 200:
        if status == 404: # this should only be here if info wasn't found twice, so assume that
            print(f'[{c.YELLOW}#{c.RES}]\tRegistration info still not found.')
        else: # any other error code
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

async def tm_url_session_wrapper(url):
    url = strip_canon(url).split('/')[0]
    async with aiohttp.ClientSession() as session:
        response = await tm_url_req(session, url, False)
        return response

async def tm_url_req(session, url, isRetry):
    # helper function to allow retries for threat_miner url scan
    addr = f"https://api.threatminer.org/v2/domain.php?q={url}"
    headers = { "Accept": "application/json" }
    async with session.get(addr, headers=headers) as response:
        r = await response.json()
        status = int(r['status_code'])
        if status == 404: # if results aren't found
            if not isRetry: # no results found on first scan, try root domain scan
                return await tm_url_req(session, get_domain(url), True)
            # else, results sent along anyway
        # if results are found, just send them along
        return [r, isRetry]

### THREATMINER (IP) #############################################
async def tm_ip_main(ip):
    scan = await tm_ip_req(ip)
    tm_ip_parse(ip, scan)

def tm_ip_parse(ip, scan):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Threat Miner{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    if scan == "not found":
        print(f'[{c.YELLOW}#{c.RES}]\tThreat Miner could not find registration info.')
        return False
    elif scan == "failed":
        print(f'[{c.RED}#{c.RES}]\tThreat Miner scan {c.RED}failed{c.RES}')
        return False
    r = scan['results'][0]
    if 'cc' in r: print(f"[{c.CYAN}#{c.RES}]\tCountry Code:\t\t{c.CYAN}{cc.codes[r['cc']]}{c.RES}")
    if 'org_name' in r: print(f"[{c.CYAN}#{c.RES}]\tOrganization:\t\t{c.CYAN}{r['org_name']}{c.RES}")
    if 'register' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['register']}{c.RES}")

async def tm_ip_req(ip):
    addr = f"https://api.threatminer.org/v2/host.php?q={ip}"
    headers = { "Accept": "application/json" }
    async with aiohttp.ClientSession() as session:
        async with session.get(addr, headers=headers) as get_resp:
            r = await get_resp.json()
            status = int(r['status_code'])
            if status != 200:
                if status == 404: return "not found"
                else: return "failed"
            return r

### GOOGLE SAFE BROWSING API v4 ##################################
async def gsb_api_main(url):
    url = canonicalize(url,True)
    scan = await gsb_api_req(url)
    gsb_api_parse(url, scan)

async def gsb_api_req(url):
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
    async with aiohttp.ClientSession() as session:
        async with session.post(addr, json=payload) as post_resp:
            r = await post_resp.json()
            return r

def gsb_api_parse(url, json):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}GSB Lookup API:{c.RES}\t{c.CYAN}{url}{c.RES}')
    r = json
    if 'matches' in r:
        for match in r['matches']:
            flag = match['threatType']
            print(f"[{c.RED}#{c.RES}]\tFlagged for: {c.RED}{flag}{c.RES}")
    else:
        print(f"[{c.CYAN}#{c.RES}]\tNo hits")

### GOOGLE SAFE BROWSING SITE REPORT #############################
async def gsb_scrape_req(url):
    url = strip_canon(url)
    asession = AsyncHTMLSession()
    addr = f'https://transparencyreport.google.com/safe-browsing/search?url={url}'

    try:
        r = await asession.get(addr)
        await r.html.arender(timeout=20)
        await asession.close()
        return r
    except Exception as e:
        # assume (or pretend) that any problems here are just timeouts
        # print(str(e))
        return "timeout"

async def gsb_scrape_main(url):
    url = strip_canon(url)
    scan = await gsb_scrape_req(url)
    gsb_scrape_parse(url, scan)

def gsb_scrape_parse(url, scan):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}GSB Site Report:{c.RES} {c.CYAN}{url}{c.RES}')
    if scan == "timeout":
        print(f"[{c.YELLOW}#{c.RES}]\tGSB Site Report timed out.")
        return False
    soup = BeautifulSoup(scan.html.html, "html.parser")
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

### POLYSWARM API -- NOT ASYNC AND CURRENTLY UNUSED ##############
def polyswarm_req(url):
    api_key = API_KEYS['polyswarm']
    api = PolyswarmAPI(key=api_key)
    instance = api.submit(url, artifact_type='url')
    result = api.wait_for(instance)
    return result

def polyswarm_main(url):
# because the api library has no asynchronous interface I can't convert it
# but I rewrote the method to separate parsing output anyway
# could rewrite without using the library?
    url = canonicalize(url,True)
    scan = polyswarm_req(url)
    return scan

def polyswarm_parse(result):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Polyswarm.io{c.RES}')
    if result.failed:
        print(f'[{c.RED}#{c.RES}]\tPolyswarm scan{c.RED}failed{c.RES}')
        return False
    positives = 0
    total = 0
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

### VIRUSTOTAL API ###############################################
async def virus_total_req(url,session):

    addr = 'https://www.virustotal.com/api/v3/urls'
    payload = {"url": url}
    headers = { "Accept": "application/json","x-apikey": API_KEYS['virustotal'],"Content-Type": "application/x-www-form-urlencoded" }

    ### change this
    async with session.post(addr, data=payload, headers=headers) as post_resp:
        pr = await post_resp.json()
        if post_resp.status == 200:
            ID = pr['data']['id']
        else:
            return "failed"
        addr = f'https://www.virustotal.com/api/v3/analyses/{ID}'
        headers = { "Accept": "application/json", "x-apikey": API_KEYS['virustotal'] }
        TIMEOUTS = 4
        while True:
            if TIMEOUTS < 0:
                return "timeout"
            async with session.get(addr, headers=headers) as get_resp:
                gr = await get_resp.json()
                if gr['data']['attributes']['status'] == 'completed':
                    break
                TIMEOUTS -= 1
                await asyncio.sleep(5)
        return gr

async def virus_total_main(url):
    async with aiohttp.ClientSession() as session:
        scan = await virus_total_req(url, session)
        virus_total_parse(url, scan)

def virus_total_parse(url, scan):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Virus Total{c.RES} scanning:\t{c.CYAN}{url}{c.RES}')
    if scan == "timeout":
        print(f'[{c.RED}#{c.RES}]\tVirus Total scan{c.RED} timed out{c.RES}')
        return False
    elif scan == "failed":
        print(f'[{c.RED}#{c.RES}]\tVirus Total scan{c.RED}failed{c.RES}')
        return False

    stats = scan['data']['attributes']['stats']
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

### PROMPTAPI WHOIS ##############################################
async def p_whois_req(url):
# seems like this can only scan root domains, so convert any urls to that first
    url = get_domain(url)
    addr = f"https://api.promptapi.com/whois/query?domain={url}"
    headers= {"apikey": API_KEYS['prompt-whois']}

    async with aiohttp.ClientSession() as session:
        async with session.get(addr, headers=headers) as get_resp:
            gr = await get_resp.json()
            status = get_resp.status
            if status != 200:
                if status == 404:
                    return "not found"
                elif status == 429:
                    return "api limit"
                else:
                    return "failed"
            return gr['result']

async def p_whois_main(url):
    scan = await p_whois_req(url)
    p_whois_parse(scan)

def p_whois_parse(scan):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Promptapi WHOIS{c.RES}')
    if scan == "not found":
        print(f'[{c.YELLOW}#{c.RES}]\tPromptapi could not find registration info.')
        return False
    elif scan == "api limit":
        print(f'[{c.YELLOW}#{c.RES}]\tExceeded daily API request limit.')
    elif scan == "failed":
        print(f'[{c.RED}#{c.RES}]\tPromptapi scan failed.')
    else:
        r = scan
        if 'domain_name' in r: print(f"[{c.CYAN}#{c.RES}]\tDomain:\t\t\t{c.CYAN}{r['domain_name']}.{c.RES}")
        if 'creation_date' in r: print(f"[{c.CYAN}#{c.RES}]\tDomain Creation Date:\t{c.CYAN}{r['creation_date']}.{c.RES}")
        if 'registrar' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrar:\t\t{c.CYAN}{r['registrar']}{c.RES}")
        if 'country' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Country:\t{c.CYAN}{cc.codes[r['country']]}{c.RES}")
        if 'org' in r: print(f"[{c.CYAN}#{c.RES}]\tRegistrant Org:\t\t{c.CYAN}{r['org']}{c.RES}")

### FRAUDGUARD.IO ################################################
async def fraudguard_req(ip):
    addr = f'https://api.fraudguard.io/ip/{ip}'
    split = API_KEYS['fraud-guard'].split('|')
    creds = aiohttp.BasicAuth(split[0],split[1])
    async with aiohttp.ClientSession() as session:
        async with session.get(addr,auth=creds) as get_resp:
            gr = await get_resp.json(content_type="text/html")
            return gr

async def fraudguard_main(ip):
    scan = await fraudguard_req(ip)
    fraudguard_parse(ip,scan)

def fraudguard_parse(ip, scan):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}Fraudguard.io{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    if not scan:
        print(f"[{c.YELLOW}#{c.RES}]\tFraudguard scan failed.")
        return False
    r = scan
    if 'country' in r: print(f"[{c.CYAN}#{c.RES}]\tCountry:\t\t{c.CYAN}{r['country']}{c.RES}")
    if 'threat' in r: print(f"[{c.CYAN}#{c.RES}]\tThreat:\t\t\t{c.CYAN}{r['threat']}{c.RES}")
    if 'risk_level' in r: print(f"[{c.CYAN}#{c.RES}]\tRisk Level:\t\t{c.CYAN}{r['risk_level']}{c.RES}")

### ABUSEIPDB ####################################################
async def abuseipdb_req(ip):
#
    endpoint = 'https://api.abuseipdb.com/api/v2/check'
    headers= {'Accept': 'application/json','Key': f"{API_KEYS['abuseipdb']}"}
    query = {'ipAddress': ip,'verbose': "True"}
    async with aiohttp.ClientSession() as session:
        async with session.get(endpoint, headers=headers, params=query) as get_resp:
            gr = await get_resp.json()
            return [gr, get_resp.status]

async def abuseipdb_main(ip):
    scan = await abuseipdb_req(ip)
    abuseipdb_parse(ip, scan[0], scan[1])

def abuseipdb_parse(ip, scan, status):
    print(f'[{c.BLUE}###{c.RES}]\t{c.BLUE}AbuseIPDB{c.RES} scanning:\t{c.CYAN}{ip}{c.RES}')
    if status != 200:
        print(f'[{c.RED}#{c.RES}]\tAbuseIPDB scan failed:')
        for err in scan['errors']:
            print(f'[{c.RED}#{c.RES}]\tStatus: {err["status"]}\tError: {err["detail"]}')
        return False
    r = scan['data']

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

#########################  UTILITIES  ############################
class c:
# color helper defs, can be reset to empty strings for colorblind-friendly output
    MAG = Fore.MAGENTA
    CYAN = Fore.CYAN
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    GRAY = Fore.WHITE
    RES = Style.RESET_ALL

class cc:
# ISO-Alpha 2 country code table
    codes = {
    "AF":"Afghanistan",
    "AL":"Albania",
    "DZ":"Algeria",
    "AS":"American Samoa",
    "AD":"Andorra",
    "AO":"Angola",
    "AI":"Anguilla",
    "AQ":"Antarctica",
    "AG":"Antigua and Barbuda",
    "AR":"Argentina",
    "AM":"Armenia",
    "AW":"Aruba",
    "AU":"Australia",
    "AT":"Austria",
    "AZ":"Azerbaijan",
    "BS":"Bahamas (the)",
    "BH":"Bahrain",
    "BD":"Bangladesh",
    "BB":"Barbados",
    "BY":"Belarus",
    "BE":"Belgium",
    "BZ":"Belize",
    "BJ":"Benin",
    "BM":"Bermuda",
    "BT":"Bhutan",
    "BO":"Bolivia (Plurinational State of)",
    "BQ":"Bonaire, Sint Eustatius and Saba",
    "BA":"Bosnia and Herzegovina",
    "BW":"Botswana",
    "BV":"Bouvet Island",
    "BR":"Brazil",
    "IO":"British Indian Ocean Territory (the)",
    "BN":"Brunei Darussalam",
    "BG":"Bulgaria",
    "BF":"Burkina Faso",
    "BI":"Burundi",
    "CV":"Cabo Verde",
    "KH":"Cambodia",
    "CM":"Cameroon",
    "CA":"Canada",
    "KY":"Cayman Islands (the)",
    "CF":"Central African Republic (the)",
    "TD":"Chad",
    "CL":"Chile",
    "CN":"China",
    "CX":"Christmas Island",
    "CC":"Cocos (Keeling) Islands (the)",
    "CO":"Colombia",
    "KM":"Comoros (the)",
    "CD":"Congo (the Democratic Republic of the)",
    "CG":"Congo (the)",
    "CK":"Cook Islands (the)",
    "CR":"Costa Rica",
    "HR":"Croatia",
    "CU":"Cuba",
    "CW":"Curaçao",
    "CY":"Cyprus",
    "CZ":"Czechia",
    "CI":"Côte d'Ivoire",
    "DK":"Denmark",
    "DJ":"Djibouti",
    "DM":"Dominica",
    "DO":"Dominican Republic (the)",
    "EC":"Ecuador",
    "EG":"Egypt",
    "SV":"El Salvador",
    "GQ":"Equatorial Guinea",
    "ER":"Eritrea",
    "EE":"Estonia",
    "SZ":"Eswatini",
    "ET":"Ethiopia",
    "FK":"Falkland Islands (the) [Malvinas]",
    "FO":"Faroe Islands (the)",
    "FJ":"Fiji",
    "FI":"Finland",
    "FR":"France",
    "GF":"French Guiana",
    "PF":"French Polynesia",
    "TF":"French Southern Territories (the)",
    "GA":"Gabon",
    "GM":"Gambia (the)",
    "GE":"Georgia",
    "DE":"Germany",
    "GH":"Ghana",
    "GI":"Gibraltar",
    "GR":"Greece",
    "GL":"Greenland",
    "GD":"Grenada",
    "GP":"Guadeloupe",
    "GU":"Guam",
    "GT":"Guatemala",
    "GG":"Guernsey",
    "GN":"Guinea",
    "GW":"Guinea-Bissau",
    "GY":"Guyana",
    "HT":"Haiti",
    "HM":"Heard Island and McDonald Islands",
    "VA":"Holy See (the)",
    "HN":"Honduras",
    "HK":"Hong Kong",
    "HU":"Hungary",
    "IS":"Iceland",
    "IN":"India",
    "ID":"Indonesia",
    "IR":"Iran (Islamic Republic of)",
    "IQ":"Iraq",
    "IE":"Ireland",
    "IM":"Isle of Man",
    "IL":"Israel",
    "IT":"Italy",
    "JM":"Jamaica",
    "JP":"Japan",
    "JE":"Jersey",
    "JO":"Jordan",
    "KZ":"Kazakhstan",
    "KE":"Kenya",
    "KI":"Kiribati",
    "KP":"Korea (the Democratic People's Republic of)",
    "KR":"Korea (the Republic of)",
    "KW":"Kuwait",
    "KG":"Kyrgyzstan",
    "LA":"Lao People's Democratic Republic (the)",
    "LV":"Latvia",
    "LB":"Lebanon",
    "LS":"Lesotho",
    "LR":"Liberia",
    "LY":"Libya",
    "LI":"Liechtenstein",
    "LT":"Lithuania",
    "LU":"Luxembourg",
    "MO":"Macao",
    "MG":"Madagascar",
    "MW":"Malawi",
    "MY":"Malaysia",
    "MV":"Maldives",
    "ML":"Mali",
    "MT":"Malta",
    "MH":"Marshall Islands (the)",
    "MQ":"Martinique",
    "MR":"Mauritania",
    "MU":"Mauritius",
    "YT":"Mayotte",
    "MX":"Mexico",
    "FM":"Micronesia (Federated States of)",
    "MD":"Moldova (the Republic of)",
    "MC":"Monaco",
    "MN":"Mongolia",
    "ME":"Montenegro",
    "MS":"Montserrat",
    "MA":"Morocco",
    "MZ":"Mozambique",
    "MM":"Myanmar",
    "NA":"Namibia",
    "NR":"Nauru",
    "NP":"Nepal",
    "NL":"Netherlands (the)",
    "NC":"New Caledonia",
    "NZ":"New Zealand",
    "NI":"Nicaragua",
    "NE":"Niger (the)",
    "NG":"Nigeria",
    "NU":"Niue",
    "NF":"Norfolk Island",
    "MP":"Northern Mariana Islands (the)",
    "NO":"Norway",
    "OM":"Oman",
    "PK":"Pakistan",
    "PW":"Palau",
    "PS":"Palestine, State of",
    "PA":"Panama",
    "PG":"Papua New Guinea",
    "PY":"Paraguay",
    "PE":"Peru",
    "PH":"Philippines (the)",
    "PN":"Pitcairn",
    "PL":"Poland",
    "PT":"Portugal",
    "PR":"Puerto Rico",
    "QA":"Qatar",
    "MK":"Republic of North Macedonia",
    "RO":"Romania",
    "RU":"Russian Federation (the)",
    "RW":"Rwanda",
    "RE":"Réunion",
    "BL":"Saint Barthélemy",
    "SH":"Saint Helena, Ascension and Tristan da Cunha",
    "KN":"Saint Kitts and Nevis",
    "LC":"Saint Lucia",
    "MF":"Saint Martin (French part)",
    "PM":"Saint Pierre and Miquelon",
    "VC":"Saint Vincent and the Grenadines",
    "WS":"Samoa",
    "SM":"San Marino",
    "ST":"Sao Tome and Principe",
    "SA":"Saudi Arabia",
    "SN":"Senegal",
    "RS":"Serbia",
    "SC":"Seychelles",
    "SL":"Sierra Leone",
    "SG":"Singapore",
    "SX":"Sint Maarten (Dutch part)",
    "SK":"Slovakia",
    "SI":"Slovenia",
    "SB":"Solomon Islands",
    "SO":"Somalia",
    "ZA":"South Africa",
    "GS":"South Georgia and the South Sandwich Islands",
    "SS":"South Sudan",
    "ES":"Spain",
    "LK":"Sri Lanka",
    "SD":"Sudan (the)",
    "SR":"Suriname",
    "SJ":"Svalbard and Jan Mayen",
    "SE":"Sweden",
    "CH":"Switzerland",
    "SY":"Syrian Arab Republic",
    "TW":"Taiwan (Province of China)",
    "TJ":"Tajikistan",
    "TZ":"Tanzania, United Republic of",
    "TH":"Thailand",
    "TL":"Timor-Leste",
    "TG":"Togo",
    "TK":"Tokelau",
    "TO":"Tonga",
    "TT":"Trinidad and Tobago",
    "TN":"Tunisia",
    "TR":"Turkey",
    "TM":"Turkmenistan",
    "TC":"Turks and Caicos Islands (the)",
    "TV":"Tuvalu",
    "UG":"Uganda",
    "UA":"Ukraine",
    "AE":"United Arab Emirates (the)",
    "GB":"United Kingdom of Great Britain and Northern Ireland (the)",
    "UM":"United States Minor Outlying Islands (the)",
    "US":"United States of America (the)",
    "UY":"Uruguay",
    "UZ":"Uzbekistan",
    "VU":"Vanuatu",
    "VE":"Venezuela (Bolivarian Republic of)",
    "VN":"Viet Nam",
    "VG":"Virgin Islands (British)",
    "VI":"Virgin Islands (U.S.)",
    "WF":"Wallis and Futuna",
    "EH":"Western Sahara",
    "YE":"Yemen",
    "ZM":"Zambia",
    "ZW":"Zimbabwe",
    "AX":"Åland Islands"
}

def colorblind():
    c.BLUE = ""
    c.CYAN = ""
    c.BLUE = ""
    c.GREEN = ""
    c.YELLOW = ""
    c.RED = ""
    c.GRAY = ""
    c.RES = ""

def clear():
# cross-platform clear terminal command
    os.system('cls||clear')

def canonicalize(url,s):
# if link is not http or https, add http/s
    if not re.match('(?:http|https)://', url):
        if s:
            return 'https://{}'.format(url)
        else:
            return 'http://{}'.format(url)
    return url

def strip_canon(url):
# if link starts with http or https, remove it
    url = re.sub('(?:http|https)://','',url).strip()
    return url

def load_api_keys():
# API helper function to load keys from ./.apis text file
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
            none_found = False
    if none_found:
        print(f"[{c.RED}#{c.RES}]\tNo API keys loaded. Functionality will be limited.")

def parse_args():
# Parse command line arguments
    ascii = """
       __ _   __ _   __ _  _ __  ___  ___   ___  __ _  _ __      _ __   _   _
      / _` | / _` | / _` || '__|/ _ \/ __| / __|/ _` || '_ \    | '_ \ | | | |
     | (_| || (_| || (_| || |  |  __/\__ \| (__| (_| || | | | _ | |_) || |_| |
      \__,_| \__, | \__, ||_|   \___||___/ \___|\__,_||_| |_|(_)| .__/  \__, |
              __/ |  __/ |                                      | |      __/ |
             |___/  |___/                                       |_|     |___/
    """
    desc = f'{c.BLUE}{ascii}\n{c.RES}by {c.GREEN}Daniel Casey{c.RES}\nVersion {c.CYAN}0.8.0{c.RES}\n{c.GRAY}Scan URLS / IPs for malicious indicators{c.RES}\n'
    parser = argparse.ArgumentParser(description=desc,allow_abbrev=False,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', type=str, help="The URL/IP to scan")
    parser.add_argument('-v', '--verbose', action="store_true", help="display verbose output")
    parser.add_argument('-q', '--quiet', action="store_true", help="remove color formatting from output")
    parser.add_argument('-k', '--keys', action="store_true", help="check status of API keys")
    args = parser.parse_args()
    return args

def parse_target(target):
# parse target string to identify whether it is Email, IP, or URL
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

def url_is_valid(url):
# utility to check if url is valid
    canon = canonicalize(url,False)
    prepared_request = PreparedRequest()
    try:
        prepared_request.prepare_url(canon, None)
    except requests.exceptions.MissingSchema as e:
        return False
    return True

def resolve_host(url):
# wrapper for socket.gethostbyname() function
# if IP can't be resolved return false
    try:
        ip = socket.gethostbyname(strip_canon(url))
        return ip
    except socket.gaierror as err:
        return False

def get_domain(url):
# try to parse out domain (NOT PERFECT)
# for ex. bbc.co.uk will break this
# need to add -f, --force for option to explicitly scan url / ip
# and warning to users to use -f if scans aren't working as desired
    url = strip_canon(url).split('/')[0]
    tokens = url.split('.')
    url = f'{tokens[-2]}.{tokens[-1]}'
    return url

#########################  MAIN LOOP  ############################
async def main():
    start = time.time() # for debugging
    logging.root.setLevel(logging.WARNING) # clean up all the noise generated by logs
    clear()
    try:
        args = parse_args()
        if args.quiet: colorblind()
        print(f'[{c.GREEN}>>>{c.RES}]\t{c.GRAY}Welcome to{c.RES} {c.GREEN}Aggrescan{c.RES}')
        if args.keys:
            print(f'[{c.GRAY}#{c.RES}]\t{c.BLUE}Keys configured:{c.RES}')
            load_api_keys()
            exit(0)
        else:
            load_api_keys()
        if not args.verbose: clear()
        target_type = parse_target(args.target.strip())
        tasks = []
        if target_type == "email":
            print(f'[{c.RED}X{c.RES}]\tEmail address scan not yet implemented.')
        elif target_type == "ip":
            # just run IP scans in this case
            ip = args.target
            print(f'[{c.GREEN}>>>{c.RES}]\tAggrescan report for IP: {c.BLUE}{ip}{c.RES}')
            tasks.append(asyncio.create_task(tm_ip_main(ip)))
            if API_KEYS['fraud-guard']: tasks.append(asyncio.create_task(fraudguard_main(ip)))
            if API_KEYS['abuseipdb']: tasks.append(asyncio.create_task(abuseipdb_main(ip)))
        elif target_type == "url":
            # run URL scans and IP scans if it resolves
            url = canonicalize(args.target,True)
            ip = resolve_host(url)
            print(f'[{c.GREEN}>>>{c.RES}]\tAggrescan report for URL: {c.BLUE}{url}{c.RES}')
            ### API SCANS ###
            if API_KEYS['urlscan']: tasks.append(asyncio.create_task(urlscan_main(url)))
            if API_KEYS['google-safe-browse']: tasks.append(asyncio.create_task(gsb_api_main(url)))
            if API_KEYS['prompt-whois']: tasks.append(asyncio.create_task(p_whois_main(url)))
            if API_KEYS['virustotal']: tasks.append(asyncio.create_task(virus_total_main(url)))
            tasks.append(asyncio.create_task(tm_url_main(url)))

            ### NON-API SCANS ###
            tasks.append(asyncio.create_task(gsb_scrape_main(url)))

            ### IP SCANS (if IP resolves)
            if ip:
                tasks.append(asyncio.create_task(tm_ip_main(ip)))
                if API_KEYS['fraud-guard']: tasks.append(asyncio.create_task(fraudguard_main(ip)))
                if API_KEYS['abuseipdb']: tasks.append(asyncio.create_task(abuseipdb_main(ip)))
        else: print(f'[{c.RED}X{c.RES}]\tUnable to determine target type. Make sure target is a valid URL or IP address.')
        await asyncio.gather(*tasks)
    except KeyboardInterrupt as e:
        print(f'[{c.GRAY}X{c.RES}]\tManually exiting Aggrescan. {c.BLUE}Goodbye.{c.RES}')

    end = time.time() # for debugging
    print(f'Time to complete: {round(end - start, 2)}') # for debugging

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
