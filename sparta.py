#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EMAIL GUARDIAN — CLI Options & Quick Usage

Usage:
  # From file
  python email_guardian.py /path/to/mail.eml

  # From stdin
  cat mail.eml | python email_guardian.py -

  # JSON output (compact / pretty)
  python email_guardian.py mail.eml --json
  python email_guardian.py mail.eml --json --pretty

  # With VirusTotal (domains/IPs/hashes)
  python email_guardian.py mail.eml --vt-api-key YOUR_VT_KEY

Common Options:
  --json               Output machine-readable JSON instead of human-readable text.
  --pretty             Pretty-print JSON (use with --json).
  --vt-api-key KEY     VirusTotal API key for reputation lookups.
  --dns-timeout SEC    DNS query timeout in seconds (default: 5.0).
  --no-color           Disable ANSI colors (useful in CI or when piping to files).
  --no-banner          Hide the ASCII banner on startup.

Exit Codes:
  0  Likely benign
  1  Suspicious
  2  Highly suspicious
  3  Error (I/O, DNS/HTTP issues, invalid input, etc.)

Examples:
  python email_guardian.py sample.eml
  python email_guardian.py sample.eml --no-banner --no-color
  python email_guardian.py sample.eml --vt-api-key $VT_API_KEY
  cat sample.eml | python email_guardian.py - --json --pretty
"""


import argparse
import sys
import re
import json
import ipaddress
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

# DNS / DKIM / SPF / HTTP
import dns.resolver
import dkim
import spf
import requests

# ---------- ANSI Colors ----------
class C:
    N = "\033[0m"
    BOLD = "\033[1m"

    # Normal + Bright
    K = "\033[30m"; R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; BL = "\033[34m"; M = "\033[35m"; CYA = "\033[36m"; W = "\033[37m"
    BRK = "\033[90m"; BR = "\033[91m"; BG = "\033[92m"; BY = "\033[93m"; BBL = "\033[94m"; BM = "\033[95m"; BC = "\033[96m"; BW = "\033[97m"

def supports_color():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def disable_colors():
    for attr in dir(C):
        if attr.isupper():
            setattr(C, attr, "")

def color_bool(v):
    if v is True: return f"{C.BG}YES{C.N}"
    if v is False: return f"{C.BR}NO{C.N}"
    return f"{C.BY}{v}{C.N}"

def color_verdict(v):
    if v == "Highly suspicious": return f"{C.BR}{v}{C.N}"
    if v == "Suspicious": return f"{C.BY}{v}{C.N}"
    return f"{C.BG}{v}{C.N}"

def thin_hr(char='-', width=78, color=C.BRK):
    print(color + (char * width) + C.N)

# 14 distinct colors (looped by index if needed)
CHECK_COLORS = [
    C.BR, C.BG, C.BY, C.BBL, C.BM, C.BC, C.BW, C.R, C.G, C.Y, C.BL, C.M, C.CYA, C.BRK
]

# ---------- BANNERS (CYBERLARGE style) ----------
BANNER_MAIN = r"""
  ______                 __   ____                     __             
 /_  __/__  ____  ____  / /  / __ \____  ____ _____  / /_____  _____ 
  / / / _ \/ __ \/ __ \/ /  / / / / __ \/ __ `/ __ \/ __/ __ \/ ___/ 
 / / /  __/ / / / /_/ / /  / /_/ / /_/ / /_/ / / / / /_/ /_/ (__  )  
/_/  \___/_/ /_/\____/_/   \____/ .___/\__,_/_/ /_/\__/\____/____/   
                                /_/                                   
"""

BANNER_SMALL = r"""
        _                      _      _ _                 _                         
   ___ | |__   ___ _ __   ___ | |__  | | | ___ _ __   ___| |__    Ahmed El-Banna   
  / _ \| '_ \ / _ \ '_ \ / _ \| '_ \ | | |/ _ \ '_ \ / __| '_ \                    
 | (_) | | | |  __/ | | | (_) | |_) || | |  __/ | | | (__| | | |                   
  \___/|_| |_|\___|_| |_|\___/|_.__/ |_|_|\___|_| |_|\___|_| |_|                   
"""

def print_banner():
    print(BANNER_MAIN.rstrip())
    print(BANNER_SMALL.rstrip())

# ---------- Regex helpers ----------
IPV4 = r'(?:\d{1,3}\.){3}\d{1,3}'
IPV6 = r'[0-9a-fA-F:]{2,}'
IP_RE = re.compile(r'\[?(' + IPV4 + r'|' + IPV6 + r')\]?')
DKIM_D_RE = re.compile(r'\bd=([^;,\s]+)', re.IGNORECASE)
DKIM_S_RE = re.compile(r'\bs=([^;,\s]+)', re.IGNORECASE)
RECEIVED_FROM_RE = re.compile(r'from\s+([^\s(]+)', re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r'by\s+([^\s(]+)', re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r'with\s+([^\s;]+)', re.IGNORECASE)
RECEIVED_FOR_RE = re.compile(r'for\s+([^;]+);', re.IGNORECASE)

# Hashes (MD5/SHA1/SHA256)
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[A-Fa-f0-9]{64}\b')

# Domains (simple but robust)
DOMAIN_RE = re.compile(r'\b((?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b')

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

CHECK_WEIGHTS = {
    "spf_dkim_dmarc_fail": 30,
    "from_returnpath_mismatch": 7,
    "replyto_domain_mismatch": 6,
    "originating_ip_unexpected_or_private": 7,
    "received_timestamps_nonmonotonic": 6,
    "x_originating_ip_present": 4,
    "suspicious_x_headers": 5,
    "dkim_domain_mismatch": 7,
    "dkim_selector_dns_missing": 3,
    "private_ip_in_received": 5,
    "missing_critical_headers": 6,
    "message_id_domain_mismatch": 4,
    "x_mailer_fake_or_old": 4,
    "no_tls_in_hops": 6
}

SUSPICIOUS_XMAILER_KEYWORDS = [
    "nodemailer", "outlook express", "custom", "curl", "python"
]

# ---------- Pretty printing helpers ----------
def section(title):
    print("\n\n", end="")  # added: two blank lines before every section
    thin_hr('-', 70, C.BRK)
    print(f"{C.BOLD}{title}{C.N}")
    thin_hr('-', 70, C.BRK)

def sub(title):
    print(f"{C.BBL}{title}{C.N}")
    thin_hr('-', 40, C.BRK)

def pad(s, w):
    s = "" if s is None else str(s)
    return s if len(s) >= w else s + ' ' * (w - len(s))

def print_kv_table(pairs, key_w=28, val_color=None):
    for k, v in pairs:
        val = "" if v is None else str(v)
        if val_color: val = val_color(val)
        print(f"{pad(k+':', key_w)} {val}")

def print_checks_table(checks):
    mapping = [
        ("spf_dkim_dmarc_fail", "Auth failures (SPF/DKIM/DMARC)"),
        ("from_returnpath_mismatch", "From vs Return-Path mismatch"),
        ("replyto_domain_mismatch", "Reply-To mismatch"),
        ("originating_ip_unexpected_or_private", "Originating IP private/unexpected"),
        ("received_timestamps_nonmonotonic", "Received timestamps non-monotonic"),
        ("x_originating_ip_present", "X-Originating-IP present"),
        ("suspicious_x_headers", "Suspicious X-* headers"),
        ("dkim_domain_mismatch", "DKIM d= vs From mismatch"),
        ("dkim_selector_dns_missing", "DKIM selector TXT missing"),
        ("private_ip_in_received", "Private IP in Received"),
        ("missing_critical_headers", "Missing critical headers"),
        ("message_id_domain_mismatch", "Message-ID domain mismatch"),
        ("x_mailer_fake_or_old", "Suspicious X-Mailer/User-Agent"),
        ("no_tls_in_hops", "No TLS in hops"),
    ]
    print(pad("Check", 44) + "Result")
    thin_hr('-', 60, C.BRK)
    for idx, (k, label) in enumerate(mapping):
        raw_val = checks.get(k)
        color = CHECK_COLORS[idx % len(CHECK_COLORS)]
        print(f"{color}{pad(label, 44)}{C.N} {color_bool(raw_val)}")

def print_hops(hops):
    headers = ["#", "Timestamp", "From host", "From IP", "By host", "With", "For"]
    widths = [3, 25, 22, 17, 22, 10, 22]
    def row(cols):
        out = []
        for i, col in enumerate(cols):
            s = "" if col is None else str(col)
            s = s.replace('\n',' ')
            out.append(pad(s, widths[i]))
        print(" ".join(out))
    print(" ".join(pad(h, widths[i]) for i,h in enumerate(headers)))
    thin_hr('-', 90, C.BRK)
    for i, hop in enumerate(hops, 1):
        row([
            i,
            hop.get('timestamp'),
            hop.get('from_hostname'),
            hop.get('from_ip'),
            hop.get('by_hostname'),
            hop.get('with'),
            (hop.get('for') or '')[:20]
        ])

def print_table(headers, rows, widths, sep_char='-'):
    header_line = "  ".join(pad(h, widths[i]) for i, h in enumerate(headers))
    print(header_line)
    thin_hr(sep_char, len(header_line), C.BRK)
    for r in rows:
        print("  ".join(pad(str(r[i]), widths[i]) for i in range(len(widths))))
        thin_hr(sep_char, len(header_line), C.BRK)

# ---------- Utils ----------
def extract_domain(address: str | None):
    if not address:
        return None
    m = re.search(r'@([A-Za-z0-9\.\-]+)', address)
    if m: return m.group(1).lower()
    tokens = re.split(r'\s|<|>|;|,', address)
    for t in tokens:
        if '.' in t and '@' not in t:
            return t.strip().lower()
    return None

def parse_received_line(raw: str):
    res = {"raw": raw, "from_hostname": None, "from_ip": None, "by_hostname": None,
           "with": None, "id": None, "for": None, "timestamp": None}
    m = RECEIVED_FROM_RE.search(raw)
    if m: res["from_hostname"] = m.group(1)
    m = IP_RE.search(raw)
    if m: res["from_ip"] = m.group(1)
    m = RECEIVED_BY_RE.search(raw)
    if m: res["by_hostname"] = m.group(1)
    m = RECEIVED_WITH_RE.search(raw)
    if m: res["with"] = m.group(1)
    m = RECEIVED_FOR_RE.search(raw)
    if m: res["for"] = m.group(1).strip()
    if ';' in raw:
        ts = raw.split(';')[-1].strip()
        try:
            dt = parsedate_to_datetime(ts)
            if dt and dt.tzinfo: res["timestamp"] = dt.isoformat()
            elif dt: res["timestamp"] = dt.replace(tzinfo=None).isoformat() + "Z"
        except Exception:
            res["timestamp"] = None
    return res

def read_raw_bytes(path: str) -> bytes:
    if path == '-' or path is None:
        return sys.stdin.buffer.read()
    with open(path, 'rb') as f:
        return f.read()

# ---------- DNS helpers ----------
def dns_txt(name: str, timeout: float = 5.0):
    try:
        return [r.to_text().strip('"') for r in dns.resolver.resolve(name, 'TXT', lifetime=timeout)]
    except dns.resolver.Timeout:
        raise RuntimeError(f"DNS timeout while querying {name}. Try increasing --dns-timeout.")
    except Exception:
        return []

def dkim_selector_exists(selector: str, d: str, timeout: float = 5.0):
    if not selector or not d: return False
    qname = f"{selector}._domainkey.{d}"
    try:
        return len(dns_txt(qname, timeout)) > 0
    except RuntimeError:
        return False

def dmarc_record(domain: str, timeout: float = 5.0):
    if not domain: return None
    recs = []
    try:
        recs = dns_txt(f"_dmarc.{domain}", timeout)
    except RuntimeError:
        return None
    for txt in recs:
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return None

def spf_record(domain: str, timeout: float = 5.0):
    if not domain: return None
    try:
        recs = dns_txt(domain, timeout)
    except RuntimeError:
        return None
    for txt in recs:
        if txt.lower().startswith("v=spf1"):
            return txt
    return None

# ---------- VirusTotal helpers ----------
def vt_lookup(endpoint: str, apikey: str, timeout: float = 10.0):
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": apikey}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "body": r.text[:400]}
    except requests.RequestException as e:
        return {"error": str(e)}

def vt_ip(ip: str, apikey: str):
    return vt_lookup(f"ip_addresses/{ip}", apikey)

def vt_domain(domain: str, apikey: str):
    return vt_lookup(f"domains/{domain}", apikey)

def vt_filehash(h: str, apikey: str):
    return vt_lookup(f"files/{h}", apikey)

def vt_parse_stats(obj):
    try:
        attrs = obj.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        return {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "total": total}
    except Exception:
        return None

def vt_badge(stats):
    if not stats or stats["total"] == 0:
        return "[N/A]"
    if stats["malicious"] > 0:
        return f"{C.BR}[MAL]{C.N}"
    if stats["suspicious"] > 0:
        return f"{C.BY}[SUS]{C.N}"
    return f"{C.BG}[OK]{C.N}"

def pct_color(count, total, kind):
    if total <= 0:
        p = "0%"
    else:
        p = f"{round((count/total)*100, 1)}%"
    if kind == "malicious":
        return f"{C.BR}{p}{C.N}"
    if kind == "suspicious":
        return f"{C.BY}{p}{C.N}"
    if kind == "harmless":
        return f"{C.BG}{p}{C.N}"
    if kind == "undetected":
        return f"{C.BRK}{p}{C.N}"
    return p

# ---------- Extraction helpers ----------
def extract_hashes(raw_text: str):
    md5s = set(MD5_RE.findall(raw_text))
    sha1s = set(SHA1_RE.findall(raw_text))
    sha256s = set(SHA256_RE.findall(raw_text))
    def cap(lst, n=50): return sorted(list(lst))[:n]
    return {"sha256": cap(sha256s), "sha1": cap(sha1s), "md5": cap(md5s)}

def extract_domains(raw_text: str):
    doms = set(DOMAIN_RE.findall(raw_text))
    filtered = []
    for d in doms:
        if d.lower().startswith("localhost"):
            continue
        filtered.append(d.lower())
    return sorted(list(set(filtered)))

# ---------- Core analyzer ----------
def analyze(raw_bytes: bytes, vt_api_key: str | None = None, dns_timeout: float = 5.0):
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    raw_headers = msg.as_bytes().decode('utf-8', errors='replace')

    parsed = {
        'from': msg.get('From'),
        'to': msg.get('To'),
        'cc': msg.get('Cc'),
        'subject': msg.get('Subject'),
        'date': msg.get('Date'),
        'message_id': msg.get('Message-ID'),
        'return_path': msg.get('Return-Path'),
        'reply_to': msg.get('Reply-To'),
        'sender': msg.get('Sender'),
        'mime_version': msg.get('MIME-Version'),
        'content_type': msg.get('Content-Type'),
        'content_transfer_encoding': msg.get('Content-Transfer-Encoding'),
        'dkim_signature': msg.get('DKIM-Signature'),
        'authentication_results': msg.get('Authentication-Results'),
        'x_headers': {k: v for k, v in msg.items() if k.startswith('X-')},
        'x_mailer': msg.get('X-Mailer') or msg.get('User-Agent'),
        'received_raw': msg.get_all('Received', []),
    }

    # Received hops
    received_hops = [parse_received_line(r) for r in parsed['received_raw']]
    parsed['received'] = received_hops
    parsed['hops'] = len(received_hops)

    # Originating IP
    originating_ip = received_hops[-1].get('from_ip') if received_hops else None
    parsed['originating_ip'] = originating_ip

    # Authentication-Results parse
    ar = (parsed['authentication_results'] or "").lower()
    spf_result = re.search(r'spf=(pass|fail|softfail|neutral|none|permerror|temperror)', ar)
    dkim_ar_result = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror|policy)', ar)
    dmarc_ar_result = re.search(r'dmarc=(pass|fail|bestguesspass|none|quarantine|reject)', ar)
    parsed['spf_result_ar'] = spf_result.group(1) if spf_result else None
    parsed['dkim_result_ar'] = dkim_ar_result.group(1) if dkim_ar_result else None
    parsed['dmarc_result_ar'] = dmarc_ar_result.group(1) if dmarc_ar_result else None

    # DKIM fields
    dkim_d, dkim_s = None, None
    if parsed['dkim_signature']:
        m = DKIM_D_RE.search(parsed['dkim_signature'])
        if m: dkim_d = m.group(1).lower()
        m = DKIM_S_RE.search(parsed['dkim_signature'])
        if m: dkim_s = m.group(1)
    parsed['dkim_d'] = dkim_d
    parsed['dkim_s'] = dkim_s

    # Message-ID domain
    msgid_domain = None
    if parsed['message_id']:
        m = re.search(r'@([A-Za-z0-9\.\-]+)', parsed['message_id'])
        if m: msgid_domain = m.group(1).lower()
    parsed['message_id_domain'] = msgid_domain

    # Missing critical headers
    missing_headers = [h for h in ['Message-ID','Date','MIME-Version','Return-Path'] if not msg.get(h)]
    parsed['missing_headers'] = missing_headers

    # Received timestamps monotonicity
    timestamps = []
    for hop in received_hops:
        ts = hop.get('timestamp')
        if ts:
            try: timestamps.append(datetime.fromisoformat(ts.replace('Z', '')))
            except: pass
    non_monotonic = any(timestamps[i] < timestamps[i-1] for i in range(1, len(timestamps))) if len(timestamps) >= 2 else False
    parsed['received_timestamps_nonmonotonic'] = non_monotonic

    # Private IPs in Received
    private_ips = []
    for hop in received_hops:
        ip = hop.get('from_ip')
        if ip:
            try:
                ipobj = ipaddress.ip_address(ip)
                if any(ipobj in net for net in PRIVATE_NETWORKS):
                    private_ips.append(ip)
            except:
                pass
    parsed['private_ips_in_received'] = private_ips

    parsed['x_originating_ip'] = msg.get('X-Originating-IP') or msg.get('X-Orig-IP') or None

    # Suspicious X headers
    suspicious_x = []
    xspam = parsed['x_headers'].get('X-Spam-Flag') or parsed['x_headers'].get('X-Spam-Status')
    if xspam and ('yes' in xspam.lower() or 'score' in xspam.lower()):
        suspicious_x.append('spam_flag')
    if parsed['x_headers'].get('Precedence', '').lower() == 'bulk':
        suspicious_x.append('precedence_bulk')
    parsed['suspicious_x_headers'] = suspicious_x

    # X-Mailer heuristic
    xm = (parsed['x_mailer'] or "").lower()
    parsed['x_mailer_suspicious'] = any(kw in xm for kw in SUSPICIOUS_XMAILER_KEYWORDS)
    parsed['x_mailer_raw'] = parsed['x_mailer']

    # TLS present?
    has_tls = any(('WITH' in (hop.get('with') or '').upper() and 'TLS' in (hop.get('with') or '').upper()) or
                  ('ESMTPS' in (hop.get('with') or '').upper()) or
                  ('SMTPS' in (hop.get('with') or '').upper())
                  for hop in received_hops)
    parsed['has_tls_in_hops'] = has_tls

    # ---------- Active DNS / crypto checks ----------
    from_domain = extract_domain(parsed['from'] or "")
    return_domain = extract_domain(parsed['return_path'] or "")
    reply_domain = extract_domain(parsed['reply_to'] or "")

    dkim_verify_ok, dkim_verify_error = None, None
    if parsed['dkim_signature']:
        try:
            dkim_verify_ok = bool(dkim.verify(raw_bytes))
        except Exception as e:
            dkim_verify_ok = False
            dkim_verify_error = str(e)

    dkim_selector_exists_flag = None
    if dkim_s and dkim_d:
        try:
            dkim_selector_exists_flag = dkim_selector_exists(dkim_s, dkim_d)
        except RuntimeError:
            dkim_selector_exists_flag = False

    spf_check = None
    if originating_ip and return_domain:
        try:
            mfrom_match = re.search(r'<\s*([^>]+)\s*>', parsed['return_path'] or '')
            mfrom = mfrom_match.group(1) if mfrom_match else f'postmaster@{return_domain}'
            helo = received_hops[0].get('from_hostname') if received_hops else return_domain
            spf_res, spf_code, spf_text = spf.check2(i=originating_ip, s=mfrom, h=helo)
            spf_check = {"result": spf_res, "code": spf_code, "text": spf_text}
        except Exception as e:
            spf_check = {"error": str(e)}

    spf_txt = spf_record(return_domain or from_domain) if (return_domain or from_domain) else None
    dmarc_txt = dmarc_record(from_domain) if from_domain else None

    dmarc_eval = None
    if dmarc_txt:
        aligned_dkim = (dkim_d == from_domain) if dkim_d and from_domain else False
        spf_pass = (spf_check and spf_check.get('result') == 'pass')
        aligned_spf = spf_pass and (return_domain == from_domain if return_domain and from_domain else False)
        dmarc_eval = {
            "record": dmarc_txt,
            "aligned_dkim": bool(aligned_dkim and dkim_verify_ok),
            "aligned_spf": bool(aligned_spf),
            "policy": re.search(r'\bp=([a-z]+)', dmarc_txt, re.IGNORECASE).group(1) if re.search(r'\bp=([a-z]+)', dmarc_txt, re.IGNORECASE) else None
        }

    # ---------- 14 checks ----------
    checks = {}
    reasons = []

    spf_fail = (parsed['spf_result_ar'] in ('fail','softfail')) or (spf_check and spf_check.get('result') in ('fail','softfail','permerror','temperror'))
    dkim_fail = (parsed['dkim_result_ar'] == 'fail') or (dkim_verify_ok is False)
    dmarc_fail = (parsed['dmarc_result_ar'] == 'fail') or (dmarc_eval and not (dmarc_eval.get('aligned_dkim') or dmarc_eval.get('aligned_spf')))
    checks['spf_dkim_dmarc_fail'] = bool(spf_fail or dkim_fail or dmarc_fail)
    if checks['spf_dkim_dmarc_fail']:
        reasons.append(f"Auth failures: SPF={parsed['spf_result_ar'] or (spf_check and spf_check.get('result'))}, DKIM={'pass' if dkim_verify_ok else 'fail' if dkim_verify_ok is False else parsed['dkim_result_ar']}, DMARC={'fail' if dmarc_fail else parsed['dmarc_result_ar']}")

    checks['from_returnpath_mismatch'] = bool(from_domain and return_domain and from_domain != return_domain)
    if checks['from_returnpath_mismatch']:
        reasons.append(f"Mismatch From ({from_domain}) vs Return-Path ({return_domain}).")

    checks['replyto_domain_mismatch'] = bool(reply_domain and from_domain and reply_domain != from_domain)
    if checks['replyto_domain_mismatch']:
        reasons.append(f"Reply-To ({reply_domain}) differs from From ({from_domain}).")

    checks['originating_ip_unexpected_or_private'] = False
    if originating_ip:
        try:
            ipobj = ipaddress.ip_address(originating_ip)
            if any(ipobj in net for net in PRIVATE_NETWORKS):
                checks['originating_ip_unexpected_or_private'] = True
                reasons.append(f"Originating IP {originating_ip} is private/reserved.")
        except:
            pass

    checks['received_timestamps_nonmonotonic'] = parsed['received_timestamps_nonmonotonic']
    if checks['received_timestamps_nonmonotonic']:
        reasons.append("Received timestamps are non-monotonic (time travel).")

    checks['x_originating_ip_present'] = bool(parsed['x_originating_ip'])
    if checks['x_originating_ip_present']:
        reasons.append(f"X-Originating-IP present: {parsed['x_originating_ip']}")

    checks['suspicious_x_headers'] = len(parsed['suspicious_x_headers']) > 0
    if checks['suspicious_x_headers']:
        reasons.append(f"Suspicious X- headers: {parsed['suspicious_x_headers']}")

    checks['dkim_domain_mismatch'] = bool(dkim_d and from_domain and dkim_d != from_domain)
    if checks['dkim_domain_mismatch']:
        reasons.append(f"DKIM d= ({dkim_d}) != From domain ({from_domain}).")

    checks['dkim_selector_dns_missing'] = (dkim_s is not None and dkim_d is not None and not dkim_selector_exists_flag)
    if checks['dkim_selector_dns_missing']:
        reasons.append(f"DKIM selector {dkim_s}._domainkey.{dkim_d} missing or no TXT.")

    checks['private_ip_in_received'] = len(private_ips) > 0
    if checks['private_ip_in_received']:
        reasons.append(f"Private/reserved IPs in Received: {private_ips}")

    checks['missing_critical_headers'] = len(missing_headers) > 0
    if checks['missing_critical_headers']:
        reasons.append(f"Missing critical headers: {missing_headers}")

    checks['message_id_domain_mismatch'] = bool(msgid_domain and from_domain and msgid_domain != from_domain)
    if checks['message_id_domain_mismatch']:
        reasons.append(f"Message-ID domain ({msgid_domain}) != From domain ({from_domain}).")

    checks['x_mailer_fake_or_old'] = parsed['x_mailer_suspicious']
    if checks['x_mailer_fake_or_old']:
        reasons.append(f"Suspicious X-Mailer/User-Agent: {parsed['x_mailer_raw']}")

    checks['no_tls_in_hops'] = not has_tls
    if checks['no_tls_in_hops']:
        reasons.append("No evidence of TLS in Received hops (ESMTPS/SMTPS/TLS).")

    # ---------- Score ----------
    total_weight = sum(CHECK_WEIGHTS.values())
    score = 0.0
    for k, w in CHECK_WEIGHTS.items():
        if checks.get(k) is True:
            score += w
    suspicion_percent = round((score / total_weight) * 100, 1)
    if suspicion_percent >= 75: verdict = "Highly suspicious"
    elif suspicion_percent >= 40: verdict = "Suspicious"
    else: verdict = "Likely benign"

    # ---------- Extract intel ----------
    raw_full_text = raw_bytes.decode('utf-8', errors='replace')
    hashes = extract_hashes(raw_full_text)
    domains = extract_domains(raw_full_text)

    # ---------- VirusTotal (optional) ----------
    intel = {}
    if vt_api_key:
        if originating_ip and re.fullmatch(IPV4, originating_ip):
            intel['vt_ip'] = vt_ip(originating_ip, vt_api_key)

        domain_set = {extract_domain(parsed['from'] or ''), extract_domain(parsed['return_path'] or ''), dkim_d}
        domain_set |= set(domains)
        intel['vt_domains'] = {d: vt_domain(d, vt_api_key) for d in sorted({d for d in domain_set if d})}

        vt_hashes = {}
        for algo in ('sha256', 'sha1', 'md5'):
            vt_hashes[algo] = {}
            for h in hashes.get(algo, []):
                vt_hashes[algo][h] = vt_filehash(h, vt_api_key)
        intel['vt_hashes'] = vt_hashes

    result = {
        "raw_headers": raw_headers,
        "parsed": parsed,
        "checks": checks,
        "reasons": reasons,
        "suspicion_score_percent": suspicion_percent,
        "verdict": verdict,
        "weights": CHECK_WEIGHTS,
        "dns": {
            "spf_txt": spf_txt,
            "dmarc_txt": dmarc_txt,
            "dkim_selector_exists": dkim_selector_exists_flag,
            "spf_check": spf_check,
            "dkim_verify_ok": dkim_verify_ok,
            "dkim_verify_error": dkim_verify_error,
            "dmarc_eval": dmarc_eval
        },
        "intel": intel,
        "extracted": {
            "hashes": hashes,
            "domains": domains
        }
    }
    return result

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Analyze raw EML headers with DNS & VirusTotal.")
    p.add_argument("input", help="Path to .eml file or '-' for stdin")
    p.add_argument("--json", action="store_true", help="Output JSON instead of human-readable format")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON (used with --json)")
    p.add_argument("--vt-api-key", dest="vt", default=None, help="VirusTotal API key (optional)")
    p.add_argument("--dns-timeout", type=float, default=5.0, help="DNS timeout seconds")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    args = p.parse_args()

    # Color handling
    if args.no_color or not supports_color():
        disable_colors()

    # Banner
    if not args.no_banner and not args.json:
        print_banner()

    try:
        raw = read_raw_bytes(args.input)
    except Exception as e:
        msg = f"{C.BR}Failed to read input{C.N}: {e}\nHint: ensure the path is correct or use '-' to read from stdin."
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            section("Error")
            print(msg)
        sys.exit(3)

    try:
        res = analyze(raw, vt_api_key=args.vt, dns_timeout=args.dns_timeout)

        if args.json:
            if args.pretty:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(json.dumps(res, ensure_ascii=False))
            v = res["verdict"]
            code = 0 if v == "Likely benign" else 1 if v == "Suspicious" else 2
            sys.exit(code)

        # Human-readable report
        section("Summary")
        print_kv_table([
            ("Verdict", color_verdict(res["verdict"])),
            ("Suspicion score (%)", res["suspicion_score_percent"]),
            ("Triggered reasons", len(res["reasons"]))
        ])
        if res["reasons"]:
            sub("Reasons")
            for r in res["reasons"]:
                print(f"- {r}")

        section("Parsed key headers")
        pz = res["parsed"]
        print_kv_table([
            ("From", pz.get("from")),
            ("Reply-To", pz.get("reply_to")),
            ("Return-Path", pz.get("return_path")),
            ("To", pz.get("to")),
            ("Cc", pz.get("cc")),
            ("Subject", pz.get("subject")),
            ("Date", pz.get("date")),
            ("Message-ID", pz.get("message_id")),
            ("MIME-Version", pz.get("mime_version")),
            ("Content-Type", pz.get("content_type")),
            ("Content-Transfer-Encoding", pz.get("content_transfer_encoding")),
            ("X-Mailer/User-Agent", pz.get("x_mailer")),
            ("Originating IP", pz.get("originating_ip")),
            ("Hops", pz.get("hops")),
        ])

        section("Checks (14 rules)")
        print_checks_table(res["checks"])

        section("Received hops")
        if pz.get("received"):
            print_hops(pz.get("received"))
        else:
            print("No Received headers found.")

        section("Authentication & DNS")
        dnsr = res["dns"]
        print_kv_table([
            ("SPF (AR)", pz.get("spf_result_ar")),
            ("SPF (pyspf)", dnsr.get("spf_check")),
            ("SPF TXT", dnsr.get("spf_txt")),
            ("DKIM verify ok", dnsr.get("dkim_verify_ok")),
            ("DKIM verify error", dnsr.get("dkim_verify_error")),
            ("DKIM d=", pz.get("dkim_d")),
            ("DKIM s=", pz.get("dkim_s")),
            ("DKIM selector exists", dnsr.get("dkim_selector_exists")),
            ("DMARC TXT", dnsr.get("dmarc_txt")),
            ("DMARC eval", dnsr.get("dmarc_eval")),
        ])

        section("Extracted indicators")
        extracted = res.get("extracted") or {}
        hashes = extracted.get("hashes") or {}
        doms = extracted.get("domains") or []

        # Hash table (no VT here; VT shown in Threat Intel)
        sub("Hashes")
        for algo in ("sha256", "sha1", "md5"):
            vals = hashes.get(algo) or []
            if not vals:
                continue
            print(f"{C.BM}{algo.upper()}{C.N}")
            headers = ["HASH", " "]
            widths = [66, 1]
            rows = [[h, ""] for h in vals]
            print_table(headers, rows, widths)

        sub("Domains")
        if doms:
            headers = ["DOMAIN", " "]
            widths = [60, 1]
            rows = [[d, ""] for d in doms]
            print_table(headers, rows, widths)
        else:
            print("No domains found.")

        if res.get("intel"):
            section("Threat Intel (VirusTotal)")
            intel = res["intel"]

            # Domains VT table with percentages
            dom_map = intel.get("vt_domains") or {}
            if dom_map:
                sub("Domains (VirusTotal)")
                headers = ["DOMAIN", "VT", "harmless", "suspicious", "malicious", "undetected", "total"]
                widths = [60, 7, 10, 11, 10, 12, 6]
                rows = []
                for d, obj in dom_map.items():
                    st = vt_parse_stats(obj)
                    if not st:
                        rows.append([d, "[N/A]", "-", "-", "-", "-", "-"])
                        continue
                    badge = vt_badge(st)
                    rows.append([
                        d,
                        badge,
                        pct_color(st["harmless"], st["total"], "harmless"),
                        pct_color(st["suspicious"], st["total"], "suspicious"),
                        pct_color(st["malicious"], st["total"], "malicious"),
                        pct_color(st["undetected"], st["total"], "undetected"),
                        str(st["total"])
                    ])
                print_table(headers, rows, widths)

            # Hashes VT table with percentages
            vt_hashes = intel.get("vt_hashes") or {}
            for algo in ("sha256", "sha1", "md5"):
                items = vt_hashes.get(algo) or {}
                if not items:
                    continue
                print(f"{C.BM}{algo.upper()} (VirusTotal){C.N}")
                headers = ["HASH", "VT", "harmless", "suspicious", "malicious", "undetected", "total"]
                widths = [66, 7, 10, 11, 10, 12, 6]
                rows = []
                for h, obj in items.items():
                    st = vt_parse_stats(obj)
                    if not st:
                        rows.append([h, "[N/A]", "-", "-", "-", "-", "-"])
                        continue
                    badge = vt_badge(st)
                    rows.append([
                        h,
                        badge,
                        pct_color(st["harmless"], st["total"], "harmless"),
                        pct_color(st["suspicious"], st["total"], "suspicious"),
                        pct_color(st["malicious"], st["total"], "malicious"),
                        pct_color(st["undetected"], st["total"], "undetected"),
                        str(st["total"])
                    ])
                print_table(headers, rows, widths)

        v = res["verdict"]
        code = 0 if v == "Likely benign" else 1 if v == "Suspicious" else 2
        sys.exit(code)

    except dns.resolver.Timeout:
        msg = f"{C.BR}DNS timeout{C.N}: increase with --dns-timeout 10 or check your resolver (UDP/53)."
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            section("Error")
            print(msg)
        sys.exit(3)
    except requests.RequestException as e:
        msg = f"{C.BR}HTTP error{C.N}: {e}\nHint: check connectivity or API key (VirusTotal)."
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            section("Error")
            print(msg)
        sys.exit(3)
    except Exception as e:
        msg = f"{C.BR}Analysis failed{C.N}: {e}\nHint: verify the input is a valid RFC822 message (.eml) or use '-' with stdin."
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            section("Error")
            print(msg)
        sys.exit(3)

if __name__ == "__main__":
    main()
