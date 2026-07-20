import json
import os
import time
import urllib.request
import urllib.error
import boto3

s3 = boto3.client('s3')
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ['DYNAMODB_TABLE']
SSM_PARAM = os.environ['ABUSEIPDB_SSM_PARAM']
LOKI_PUSH_URL = os.environ['LOKI_PUSH_URL']
LOKI_SECRET_SSM_PARAM = os.environ['LOKI_SECRET_SSM_PARAM']
TTL_SECONDS = 90 * 24 * 60 * 60  # 90 days

table = dynamodb.Table(TABLE_NAME)
_api_key_cache = None
_loki_secret_cache = None


def get_api_key():
    global _api_key_cache
    if _api_key_cache is None:
        resp = ssm.get_parameter(Name=SSM_PARAM, WithDecryption=True)
        _api_key_cache = resp['Parameter']['Value']
    return _api_key_cache


def get_loki_secret():
    global _loki_secret_cache
    if _loki_secret_cache is None:
        resp = ssm.get_parameter(Name=LOKI_SECRET_SSM_PARAM, WithDecryption=True)
        _loki_secret_cache = resp['Parameter']['Value']
    return _loki_secret_cache


def already_checked(ip):
    resp = table.get_item(Key={'src_ip': ip})
    return 'Item' in resp


def check_abuseipdb(ip, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={'Key': api_key, 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())['data']
    except urllib.error.URLError as e:
        print(f"AbuseIPDB request failed for {ip}: {e}")
        return None


def store_result(ip, result):
    now = int(time.time())
    item = {
        'src_ip': ip,
        'abuse_confidence_score': result.get('abuseConfidenceScore', 0) if result else -1,
        'total_reports': result.get('totalReports', 0) if result else 0,
        'country_code': result.get('countryCode', 'unknown') if result else 'unknown',
        'isp': result.get('isp', 'unknown') if result else 'unknown',
        'last_checked': now,
        'expires_at': now + TTL_SECONDS,
    }
    table.put_item(Item=item)
    return item


def extract_ips_from_log(content):
    ips = set()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        ip = entry.get('src_ip')
        if ip:
            ips.add(ip)
    return ips


def push_to_loki(results):
    if not results:
        return
    secret = get_loki_secret()
    base_ns = int(time.time() * 1e9)
    values = []
    for i, item in enumerate(results):
        ts_ns = str(base_ns + i)  # nanoseconds must be strictly increasing per entry
        values.append([ts_ns, json.dumps(item)])

    payload = {
        "streams": [
            {
                "stream": {"service": "cloud-siem-threat-intel"},
                "values": values
            }
        ]
    }

    req = urllib.request.Request(
        LOKI_PUSH_URL,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            "Content-Type": "application/json",
            "X-Loki-Push-Secret": secret
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"Loki push status: {resp.status}")
    except urllib.error.URLError as e:
        print(f"Loki push failed: {e}")


def handler(event, context):
    api_key = None
    results_for_loki = []

    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        if key.startswith('cloudtrail-logs/'):
            print(f"Skipping CloudTrail object: {key}")
            continue
        print(f"Processing s3://{bucket}/{key}")

        obj = s3.get_object(Bucket=bucket, Key=key)
        content = obj['Body'].read().decode('utf-8', errors='ignore')
        ips = extract_ips_from_log(content)
        print(f"Found {len(ips)} unique IPs in {key}")

        for ip in ips:
            if already_checked(ip):
                print(f"Skipping {ip}, already checked")
                continue
            if api_key is None:
                api_key = get_api_key()
            result = check_abuseipdb(ip, api_key)
            stored_item = store_result(ip, result)
            results_for_loki.append(stored_item)
            print(f"Checked {ip}: {result}")

    push_to_loki(results_for_loki)

    return {"status": "ok", "ips_checked": len(results_for_loki)}