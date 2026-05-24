#!/usr/bin/env python3
"""
IOC Enrichment Script
Enriches IPs, domains, and file hashes via multiple threat intelligence sources.
Supports: VirusTotal, AbuseIPDB, Shodan, URLScan.io

Usage:
    python enrich_ioc.py --ioc 8.8.8.8 --type ip
    python enrich_ioc.py --ioc evil.com --type domain
    python enrich_ioc.py --ioc d41d8cd98f00b204e9800998ecf8427e --type hash
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime

import requests
from utils.logger import setup_logger
from utils.api_client import APIClient

logger = setup_logger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
VT_API_KEY = os.getenv('VT_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

VT_BASE_URL = 'https://www.virustotal.com/api/v3'
ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'


# ─── VirusTotal ───────────────────────────────────────────────────────────────
def enrich_virustotal(ioc: str, ioc_type: str) -> dict:
    """Look up an IOC on VirusTotal."""
    if not VT_API_KEY:
        logger.warning("VT_API_KEY not set — skipping VirusTotal enrichment")
        return {}

    headers = {'x-apikey': VT_API_KEY}
    endpoint_map = {
        'ip':     f'/ip_addresses/{ioc}',
        'domain': f'/domains/{ioc}',
        'hash':   f'/files/{ioc}',
        'url':    f'/urls/{ioc}',
    }
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {}

    try:
        resp = requests.get(f'{VT_BASE_URL}{endpoint}', headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json().get('data', {}).get('attributes', {})
        stats = data.get('last_analysis_stats', {})
        return {
            'source': 'virustotal',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'reputation': data.get('reputation', 'unknown'),
            'categories': data.get('categories', {}),
            'country': data.get('country', ''),
            'verdict': 'MALICIOUS' if stats.get('malicious', 0) > 3 else
                       'SUSPICIOUS' if stats.get('suspicious', 0) > 3 else 'CLEAN',
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal lookup failed for {ioc}: {e}")
        return {'source': 'virustotal', 'error': str(e)}


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
def enrich_abuseipdb(ip: str) -> dict:
    """Check IP reputation on AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB enrichment")
        return {}

    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}

    try:
        resp = requests.get(f'{ABUSEIPDB_BASE_URL}/check', headers=headers,
                           params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get('data', {})
        return {
            'source': 'abuseipdb',
            'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
            'country_code': data.get('countryCode', ''),
            'isp': data.get('isp', ''),
            'total_reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReportedAt', ''),
            'verdict': 'MALICIOUS' if data.get('abuseConfidenceScore', 0) > 70 else
                       'SUSPICIOUS' if data.get('abuseConfidenceScore', 0) > 25 else 'CLEAN',
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {'source': 'abuseipdb', 'error': str(e)}


# ─── Aggregator ───────────────────────────────────────────────────────────────
def enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """Aggregate enrichment from all available sources."""
    logger.info(f"Enriching {ioc_type}: {ioc}")

    results = {
        'ioc': ioc,
        'type': ioc_type,
        'timestamp': datetime.utcnow().isoformat(),
        'enrichments': [],
    }

    # VirusTotal (all types)
    vt_result = enrich_virustotal(ioc, ioc_type)
    if vt_result:
        results['enrichments'].append(vt_result)

    # AbuseIPDB (IP only)
    if ioc_type == 'ip':
        abuse_result = enrich_abuseipdb(ioc)
        if abuse_result:
            results['enrichments'].append(abuse_result)

    # Aggregate final verdict
    verdicts = [e.get('verdict', 'UNKNOWN') for e in results['enrichments']]
    if 'MALICIOUS' in verdicts:
        results['final_verdict'] = 'MALICIOUS'
    elif 'SUSPICIOUS' in verdicts:
        results['final_verdict'] = 'SUSPICIOUS'
    else:
        results['final_verdict'] = 'CLEAN'

    logger.info(f"Final verdict for {ioc}: {results['final_verdict']}")
    return results


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Enrich IOCs via threat intelligence sources')
    parser.add_argument('--ioc', required=True, help='IOC value to enrich')
    parser.add_argument('--type', required=True, choices=['ip', 'domain', 'hash', 'url'],
                        dest='ioc_type', help='IOC type')
    parser.add_argument('--output', choices=['json', 'text'], default='text',
                        help='Output format')
    args = parser.parse_args()

    result = enrich_ioc(args.ioc, args.ioc_type)

    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*50}")
        print(f"IOC: {result['ioc']} ({result['type']})")
        print(f"Final Verdict: {result['final_verdict']}")
        print(f"Timestamp: {result['timestamp']}")
        for enrichment in result['enrichments']:
            print(f"\n[{enrichment['source'].upper()}]")
            for k, v in enrichment.items():
                if k != 'source':
                    print(f"  {k}: {v}")
        print('='*50)

    return 0 if result['final_verdict'] != 'MALICIOUS' else 1


if __name__ == '__main__':
    sys.exit(main())
