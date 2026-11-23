# IOC check tool
# 1: Takes IPs from ips.txt, checks them on AbuseIPDB and VirusTotal,
#         and saves the result in results.csv
# 2: Takes file hashes from fim_iocs.txt (made by fim.py), checks them
#         on VirusTotal, and saves the result in hash_results.csv

# How to run:
# 1. pip install requests
# 2. make free accounts on AbuseIPDB and VirusTotal and get your api keys
# 3. set the keys in terminal (powershell), don't write them in the code:
#       $env:ABUSEIPDB_KEY="your key"
#       $env:VT_KEY="your key"
# 4. make a file ips.txt in the same folder, one IP in each line
#    (optional) run fim.py to make fim_iocs.txt for the hash check
# 5. run: python ioc_check.py
# (keys work only in the same terminal window where you set them)

import os
import sys
import requests
import ipaddress
import time
import csv

# AbuseIPDB
API_KEY = os.getenv("ABUSEIPDB_KEY")   # key is taken from terminal, not from code
URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip):
    # asks AbuseIPDB about one IP
    headers = {"Key" : API_KEY, "Accept" : "application/json"}
    params = {"ipAddress" : ip, "maxAgeInDays" : 90}   # only last 90 days reports
    r = requests.get(URL, headers=headers, params=params, timeout=10)
    r.raise_for_status()   # gives error if key is wrong or limit is over
    return r.json()["data"]

# VirusTotal
VT_KEY = os.getenv("VT_KEY")
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def check_vt(ip):
    # asks VirusTotal, returns how many vendors said malicious/suspicious etc
    headers = {"x-apikey" : VT_KEY}
    r = requests.get(VT_URL + ip, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]

def enrich(ip):
    # this also checks if the IP is valid (wrong IP gives ValueError)
    ip_obj = ipaddress.ip_address(ip)

    # private IPs (10.x, 192.168.x) are not on internet, so no need
    if ip_obj.is_private:
        return None

    d = check_ip(ip)
    vt = check_vt(ip)
    score = d["abuseConfidenceScore"]

    # verdict is made only from AbuseIPDB score
    if score >= 75:
        verdict = "Malicious"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    # order should be same as the header in the csv below
    return [d["ipAddress"], score, verdict, d["countryCode"],
            d["totalReports"], vt["malicious"], vt["suspicious"]]


# ---------- Part 2: file hashes (from fim.py) ----------
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/"

def read_hashes(filename):
    # fim_iocs.txt has lines like "SHA-256: <hash>"
    # it will take only SHA-256 lines, because MD5, SHA-1 and SHA-256 are of the same file and checking all three would waste VirusTotal requests
     
    hashes = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if ": " in line:
                label, value = line.split(": ", 1)
                   # skip the hash if we already have it
                if label == "SHA-256" and value not in hashes:
                    hashes.append(value)
    return hashes

def check_vt_hash(file_hash):
    # asks VirusTotal about one file hash
    headers = {"x-apikey" : VT_KEY}
    r = requests.get(VT_FILE_URL + file_hash, headers=headers, timeout=10)
    if r.status_code == 404:
        return None   # because VirusTotal has never seen this file
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]

def enrich_hash(file_hash):
    stats = check_vt_hash(file_hash)

    if stats is None:
        # not found does NOT mean the file is safe, it just means VirusTotal doesn't know about it
        return [file_hash, "Not found", "", ""]

    # verdict is made from how many vendors said malicious
    if stats["malicious"] >= 5:
        verdict = "Malicious"
    elif stats["malicious"] >= 1:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    # order should be same as the header in the hash csv below
    return [file_hash, verdict, stats["malicious"], stats["suspicious"]]


if __name__ == "__main__":

    # stop if keys are not set
    if not API_KEY or not VT_KEY:
        print("Set ABUSEIPDB_KEY and VT_KEY first")
        sys.exit(1)

    typed = input("Enter one IP (or press Enter to use ips.txt and fim_iocs.txt): ").strip()

    if typed:
        # ----- single IP: show the result in terminal only -----
        try:
            row = enrich(typed)
        except (ValueError, requests.RequestException) as e:
            print(f"{typed} : error {e}")
            sys.exit(1)

        if row is None:
            print(f"{typed} : Private IP, Skipped")
        else:
            print(f"IP            : {row[0]}")
            print(f"Verdict       : {row[2]}")
            print(f"Abuse score   : {row[1]}")
            print(f"Country       : {row[3]}")
            print(f"Reports       : {row[4]}")
            print(f"VT malicious  : {row[5]}")
            print(f"VT suspicious : {row[6]}")
        sys.exit(0)   # stop here, so the file parts below do not run
        
    # ----- Part 1: IPs -----
    if os.path.exists("ips.txt"):
        # read IPs from the file, skip empty lines
        with open("ips.txt") as f:
            ips = [line.strip() for line in f if line.strip()]

        # results.csv gets overwritten every time you run
        with open("results.csv", "w", newline="") as out:
            writer = csv.writer(out)
            writer.writerow(["ip", "abuse_score", "verdict", "country", "reports", "vt_malicious", "vt_suspicious"])
            for ip in ips:
                try:
                    row = enrich(ip)
                except (ValueError, requests.RequestException) as e:
                    # wrong IP or api problem, just print and move to next IP
                    print(f"{ip} : error {e}")
                    continue
                if row:
                    writer.writerow(row)
                    print(f"{ip} : done")
                    time.sleep(15)   # VirusTotal free allows only 4 requests per minute
                else:
                    print(f"{ip} : Private IP, Skipped")
    else:
        print("ips.txt not found, skipping IP check")

    # ----- Part 2: file hashes -----
    if os.path.exists("fim_iocs.txt"):
        hashes = read_hashes("fim_iocs.txt")

        # hash_results.csv gets overwritten every time you run
        with open("hash_results.csv", "w", newline="") as out:
            writer = csv.writer(out)
            writer.writerow(["sha256", "verdict", "vt_malicious", "vt_suspicious"])
            for h in hashes:
                try:
                    row = enrich_hash(h)
                except requests.RequestException as e:
                    print(f"{h} : error {e}")
                    continue
                writer.writerow(row)
                print(f"{h} : {row[1]}")
                time.sleep(15)   # same VirusTotal limit
    else:
        print("fim_iocs.txt not found, skipping hash check")
