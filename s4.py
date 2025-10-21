import argparse
import boto3
import requests
import xml.etree.ElementTree as ET
import re
import os
import time
import random
import concurrent.futures
from pathlib import Path
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError

# Initialize S3 client with unsigned requests
s3_client = boto3.client("s3", config=Config(signature_version=UNSIGNED))

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

# Default per-bucket download cap to avoid one huge bucket consuming the run
DEFAULT_PER_BUCKET_DOWNLOADS = 50

# Defaults for concurrency and download behavior
DEFAULT_CONCURRENCY = 8
DEFAULT_DOWNLOAD_TIMEOUT = 60
DEFAULT_DOWNLOAD_RETRIES = 2


def is_valid_bucket_line(raw: str) -> bool:
    """Return True if the line looks like a plausible bucket identifier.

    Reject lines that are clearly descriptive text, contain spaces, parentheses,
    start with a dash (bullet), or contain wildcard '*' characters.
    """
    if not raw or not raw.strip():
        return False
    r = raw.strip()
    # If it contains spaces, parentheses, or wildcard characters, skip it
    if ' ' in r or '(' in r or ')' in r or '*' in r:
        return False
    # Skip bullet points that start with '-'
    if r.startswith('-'):
        return False
    # Very short labels like 'text' are not bucket names
    if r.lower() == 'text' or len(r) < 2:
        return False
    return True


def key_matches_keywords(key: str, include_keywords, exclude_keywords) -> bool:
    """Return True when the key passes keyword include/exclude filters."""
    key_lower = key.lower()
    if include_keywords and not any(keyword in key_lower for keyword in include_keywords):
        return False
    if exclude_keywords and any(keyword in key_lower for keyword in exclude_keywords):
        return False
    return True


def record_hit(hits_config, raw_bucket: str, key: str, source: str) -> None:
    """Write high-value hits to the configured sink."""
    if not hits_config:
        return

    key_lower = key.lower()
    keywords = hits_config.get("keywords") or []
    regexes = hits_config.get("regexes") or []

    matched = False
    if keywords and any(keyword in key_lower for keyword in keywords):
        matched = True
    else:
        for regex in regexes:
            if regex.search(key):
                matched = True
                break
    if not matched:
        return

    identifier = f"{raw_bucket}/{key}"
    seen = hits_config.setdefault("seen", set())
    if identifier in seen:
        return
    seen.add(identifier)

    line = f"{identifier} [{source}]\n"
    hits_path = hits_config.get("path")
    if hits_path:
        path = Path(hits_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a', encoding='utf-8') as handle:
            handle.write(line)
    else:
        print(f"HIT: {identifier} [{source}]")

def get_output_filename(base_name, index):
    name, ext = os.path.splitext(base_name)
    return f"{name}_part{index}{ext}"

def write_with_rotation(base_name, data, file_index):
    file_path = get_output_filename(base_name, file_index)
    if os.path.exists(file_path) and os.path.getsize(file_path) >= MAX_FILE_SIZE:
        file_index += 1
        file_path = get_output_filename(base_name, file_index)
    with open(file_path, 'a') as f:
        f.write(data)
    return file_index


def download_object(bucket, key, download_dir, s3c=None, size=None, provider='aws', extra=None):
    """Download a single S3 object to download_dir/bucket/key (creates dirs).

    Skips download if the object's size exceeds MAX_FILE_SIZE. Returns True
    on success, False otherwise.
    """
    # NOTE: This function previously relied on a global s3_client. To allow
    # per-bucket S3-compatible endpoints (e.g. DigitalOcean Spaces) we now
    # accept a client keyword argument via callers (see list_objects).
    # For backward compatibility, callers may still omit s3c and the global
    # unsigned s3_client will be used.
    if s3c is None:
        s3c = globals().get("s3_client")
    if extra is None:
        extra = {}

    # If caller provided a size (from listing), avoid an extra HEAD request.
    if size is None and s3c is not None:
        try:
            head = s3c.head_object(Bucket=bucket, Key=key)
            size = head.get('ContentLength', 0)
        except ClientError:
            # If HEAD is forbidden (403) or fails, we'll attempt direct download
            # via boto3 or HTTP candidates below instead of giving up now.
            size = None

    if size is not None and size > MAX_FILE_SIZE:
        print(f"Skipping {key} ({size} bytes) - exceeds MAX_FILE_SIZE")
        return False

    local_path = os.path.join(download_dir, bucket, key)
    local_dir = os.path.dirname(local_path)
    os.makedirs(local_dir, exist_ok=True)

    # Attempt download via boto3 client when available.
    if s3c is not None:
        try:
            s3c.download_file(bucket, key, local_path)
            print(f"Downloaded {bucket}/{key} -> {local_path}")
            return True
        except ClientError as e:
            # If access is forbidden or other error, fall back to HTTP candidates.
            print(f"Boto3 download failed for {bucket}/{key}: {e}")

    # Fall back to HTTP candidate URLs (works for public objects across providers).
    ok = http_download_candidates(provider, bucket, extra or {}, key, local_path)
    if not ok:
        print(f"HTTP download failed for {bucket}/{key}")
    return ok


def parse_bucket_identifier(raw: str):
    """Parse a raw bucket identifier and return (provider, bucket, extra).

    provider: 'aws'|'do'|'gcs'|'azure'|'unknown'
    bucket: extracted bucket name to pass to S3 APIs
    extra: dict with optional keys like 'region' or 'endpoint'
    """
    raw = raw.strip().lower()
    # DigitalOcean Spaces: <bucket>.<region>.digitaloceanspaces.com
    m = re.match(r"^([^.]+)\.([^.]+)\.digitaloceanspaces\.com$", raw)
    if m:
        return "do", m.group(1), {"region": m.group(2), "endpoint": f"https://{m.group(2)}.digitaloceanspaces.com"}

    # AWS virtual-hosted style: <bucket>.s3-<region>.amazonaws.com or <bucket>.s3.<region>.amazonaws.com or <bucket>.s3.amazonaws.com
    m = re.match(r"^([^.]+)\.s3[.-]([^.]+)\.amazonaws\.com$", raw)
    if m:
        return "aws", m.group(1), {"region": m.group(2)}
    m = re.match(r"^([^.]+)\.s3\.amazonaws\.com$", raw)
    if m:
        return "aws", m.group(1), {}

    # GCS: <bucket>.storage.googleapis.com
    m = re.match(r"^([^.]+)\.storage\.googleapis\.com$", raw)
    if m:
        return "gcs", m.group(1), {}

    # Azure Blob Storage: <bucket>.blob.core.windows.net
    m = re.match(r"^([^.]+)\.blob\.core\.windows\.net$", raw)
    if m:
        return "azure", m.group(1), {}

    # If the raw string contains amazonaws and looks like host, try to extract bucket before first dot
    if "amazonaws.com" in raw and ".s3" in raw:
        parts = raw.split('.')
        return "aws", parts[0], {}

    # If it's a plain single-label name, assume AWS S3 bucket.
    if "." not in raw:
        return "aws", raw, {}

    return "unknown", raw, {}

def list_objects(bucket, output_file, max_files, include_types, exclude_types, include_keywords, exclude_keywords, prefix='', delimiter='', continuation_token=None, file_index=1, download_dir=None, executor=None, download_timeout=DEFAULT_DOWNLOAD_TIMEOUT, download_retries=DEFAULT_DOWNLOAD_RETRIES, hits_config=None, raw_bucket=None):
    """
    List objects in an S3 bucket up to a specified maximum number of files.
    """
    # Support passing a tuple (bucket_name, s3_client) via bucket when
    # process_buckets creates per-provider clients. If bucket is a tuple, unpack.
    s3c = s3_client
    bucket_name = bucket
    # bucket can be: plain name, or tuple (name, s3_client) or (name, s3_client, provider, extra)
    bucket_name = bucket
    provider = 'aws'
    extra = {}
    if isinstance(bucket, tuple):
        if len(bucket) >= 2:
            bucket_name, s3c = bucket[0], bucket[1]
        if len(bucket) >= 3:
            provider = bucket[2]
        if len(bucket) >= 4:
            extra = bucket[3]

    raw_id = raw_bucket or bucket_name

    kwargs = {
        'Bucket': bucket_name,
        'Prefix': prefix,
        'Delimiter': delimiter,
        'MaxKeys': 100000
    }

    if continuation_token:
        kwargs['ContinuationToken'] = continuation_token

    try:
        response = s3c.list_objects_v2(**kwargs)
    except ClientError as e:
        print(f"Error accessing bucket '{bucket_name}': {e}")
        return False, file_index

    file_count = 0
    downloads_done = 0
    # We'll collect futures if an executor is provided so we can enforce per-download timeouts
    futures = []

    for obj in response.get('Contents', []):
        key = obj['Key']
        if key.endswith('/'):
            continue
        if include_types and not any(key.endswith(ext) for ext in include_types):
            continue
        if exclude_types and any(key.endswith(ext) for ext in exclude_types):
            continue
        if not key_matches_keywords(key, include_keywords, exclude_keywords):
            continue

        record_hit(hits_config, raw_id, key, "list")

        if file_count >= max_files:
            return False, file_index

        line = 'File: ' + key + '\n'
        print('File:', key)
        file_index = write_with_rotation(output_file, line, file_index)
        if download_dir:
            # Best-effort download; submit to executor if provided, else run inline.
            try:
                per_bucket_cap = getattr(s3c, '_per_bucket_cap', globals().get('PER_BUCKET_DOWNLOADS', DEFAULT_PER_BUCKET_DOWNLOADS))
                if downloads_done < per_bucket_cap:
                    if executor is not None:
                        fut = executor.submit(download_object, bucket_name, key, download_dir, s3c, obj.get('Size'), provider, extra)
                        futures.append((fut, bucket_name, key))
                    else:
                        ok = download_object(bucket_name, key, download_dir, s3c=s3c, size=obj.get('Size'), provider=provider, extra=extra)
                        if ok:
                            downloads_done += 1
                else:
                    # Reached per-bucket cap; skip further downloads for this bucket.
                    pass
            except Exception as e:
                print(f"Error scheduling download {bucket_name}/{key}: {e}")
        file_count += 1

    for common_prefix in response.get('CommonPrefixes', []):
        line = 'Folder: ' + common_prefix['Prefix'] + '\n'
        print('Folder:', common_prefix['Prefix'])
        file_index = write_with_rotation(output_file, line, file_index)

    # If we submitted futures, wait for them with timeouts and count successes.
    for fut, bkt, k in futures:
        try:
            ok = fut.result(timeout=download_timeout)
            if ok:
                downloads_done += 1
        except concurrent.futures.TimeoutError:
            print(f"Download timed out for {bkt}/{k}")
            try:
                fut.cancel()
            except Exception:
                pass
        except Exception as e:
            print(f"Download failed for {bkt}/{k}: {e}")

    if response.get('IsTruncated') and file_count < max_files:
        return list_objects(
            (bucket_name, s3c, provider, extra) if s3c is not s3_client else bucket_name,
            output_file,
            max_files - file_count,
            include_types,
            exclude_types,
            include_keywords,
            exclude_keywords,
            prefix,
            delimiter,
            response.get('NextContinuationToken'),
            file_index,
            download_dir,
            executor=executor,
            download_timeout=download_timeout,
            download_retries=download_retries,
            hits_config=hits_config,
            raw_bucket=raw_id,
        )

    return True, file_index


def http_list_s3_host(host: str, max_files: int = 1000):
    """Try HTTP listing against a virtual-host S3 endpoint.

    Returns a list of object keys (may be empty) or raises on network errors.
    """
    url = f"https://{host}/?list-type=2"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except Exception:
        return []
    keys = []
    try:
        root = ET.fromstring(r.text)
        for elem in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
            k = elem.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
            if k is not None and k.text:
                keys.append(k.text)
                if len(keys) >= max_files:
                    break
    except ET.ParseError:
        return []
    return keys


def http_list_gcs(bucket: str, max_files: int = 1000):
    url = f"https://storage.googleapis.com/{bucket}?delimiter=/"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except Exception:
        return []
    keys = []
    try:
        root = ET.fromstring(r.text)
        for elem in root.findall('.//{http://doc.s3.amazonaws.com/2006-03-01/}Contents'):
            k = elem.find('{http://doc.s3.amazonaws.com/2006-03-01/}Key')
            if k is not None and k.text:
                keys.append(k.text)
                if len(keys) >= max_files:
                    break
    except ET.ParseError:
        return []
    return keys


def http_list_azure(container: str, max_files: int = 1000):
    url = f"https://{container}.blob.core.windows.net/?restype=container&comp=list"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except Exception:
        return []
    keys = []
    try:
        root = ET.fromstring(r.text)
        for elem in root.findall('.//Blob'):
            name = elem.find('Name')
            if name is not None and name.text:
                keys.append(name.text)
                if len(keys) >= max_files:
                    break
    except ET.ParseError:
        return []
    return keys


def http_download_candidates(provider, bucket, extra, key, local_path):
    """Try candidate public URLs for provider to download the object.

    Returns True on success.
    """
    candidates = []
    if provider == 'aws':
        # Try common virtual-host styles
        candidates = [
            f"https://{bucket}.s3.amazonaws.com/{key}",
            f"https://{bucket}.s3-us-east-1.amazonaws.com/{key}",
            f"https://{bucket}.s3-us-west-2.amazonaws.com/{key}",
        ]
    elif provider == 'do':
        region = extra.get('region')
        candidates = [f"https://{bucket}.{region}.digitaloceanspaces.com/{key}"]
    elif provider == 'gcs':
        candidates = [f"https://storage.googleapis.com/{bucket}/{key}", f"https://{bucket}.storage.googleapis.com/{key}"]
    elif provider == 'azure':
        candidates = [f"https://{bucket}.blob.core.windows.net/{key}"]
    else:
        # For unknown providers, try treating raw as a host.
        candidates = [f"https://{bucket}/{key}"]

    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    # Try each candidate URL with a small number of retries and exponential backoff
    for url in candidates:
        attempt = 0
        while attempt <= globals().get('DOWNLOAD_RETRIES', DEFAULT_DOWNLOAD_RETRIES):
            try:
                with requests.get(url, stream=True, timeout=30) as r:
                    if r.status_code == 200:
                        with open(local_path, 'wb') as f:
                            for chunk in r.iter_content(1024 * 64):
                                if chunk:
                                    f.write(chunk)
                        print(f"HTTP downloaded {url} -> {local_path}")
                        return True
                    else:
                        # non-200 -> break to next URL after retries
                        pass
            except Exception:
                pass
            # backoff before next attempt
            attempt += 1
            sleep_for = (2 ** attempt) + random.random()
            time.sleep(min(sleep_for, 30))
    return False

def process_buckets(
    bucket_list_file,
    output_file,
    max_files_per_bucket,
    include_types,
    exclude_types,
    include_keywords,
    exclude_keywords,
    bucket_include_keywords=None,
    bucket_exclude_keywords=None,
    hits_config=None,
    download_dir=None,
):
    """
    Process multiple buckets listed in a text file.
    """
    with open(bucket_list_file, 'r') as file:
        buckets = [line.strip() for line in file.readlines()]

    bucket_include_keywords = bucket_include_keywords or []
    bucket_exclude_keywords = bucket_exclude_keywords or []

    file_index = 1
    # Create a thread pool for downloads
    concurrency = globals().get('CONCURRENCY', DEFAULT_CONCURRENCY)
    download_timeout = globals().get('DOWNLOAD_TIMEOUT', DEFAULT_DOWNLOAD_TIMEOUT)
    download_retries = globals().get('DOWNLOAD_RETRIES', DEFAULT_DOWNLOAD_RETRIES)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        for raw in buckets:
            # Skip empty lines
            if not raw:
                continue
            # Skip lines that are obviously descriptive or patterns and not valid
            # bucket identifiers (contain spaces, parentheses, start with '-', or
            # contain literal '*' wildcards). These are present in the heuristic
            # buckets.txt and should not be treated as bucket names.
            if not is_valid_bucket_line(raw):
                print(f"Skipping non-bucket line: {raw}")
                continue

            lowered_raw = raw.lower()
            if bucket_include_keywords and not any(keyword in lowered_raw for keyword in bucket_include_keywords):
                print(f"Skipping bucket {raw} due to bucket include filters")
                continue
            if bucket_exclude_keywords and any(keyword in lowered_raw for keyword in bucket_exclude_keywords):
                print(f"Skipping bucket {raw} due to bucket exclude filters")
                continue

            provider, name, extra = parse_bucket_identifier(raw)
            print(f"Processing bucket: {raw} -> provider={provider}, name={name}")

            if provider in ("gcs", "azure"):
                print(f"Skipping unsupported provider '{provider}' for {raw}")
                continue

            if provider == "unknown" and "." in raw:
                # Many entries are host-style names from multiple providers; if
                # we cannot confidently map them to an S3-compatible bucket name,
                # skip them to avoid NoSuchBucket noise. Users can provide
                # explicit, normalized bucket names if desired.
                print(f"Skipping unknown host-style identifier: {raw}")
                continue

            # Prepare header using the raw identifier for traceability.
            header = f"\n--- Bucket: {raw} (resolved: {name}) ---\n"
            file_index = write_with_rotation(output_file, header, file_index)

            # Create per-bucket client for DigitalOcean Spaces (endpoint style).
            s3c = s3_client
            if provider == "do":
                region = extra.get("region")
                endpoint = extra.get("endpoint")
                try:
                    s3c = boto3.client("s3", config=Config(signature_version=UNSIGNED), endpoint_url=endpoint)
                except Exception as e:
                    print(f"Failed to create DO Spaces client for {raw}: {e}")
                    continue

            try:
                # Pass a tuple (bucket_name, client) so list_objects can use it.
                target = (name, s3c, provider, extra) if s3c is not s3_client else name
                # Communicate per-bucket download cap to the client object
                setattr(s3c, '_per_bucket_cap', globals().get('PER_BUCKET_DOWNLOADS', DEFAULT_PER_BUCKET_DOWNLOADS))
                # Pass executor and download policy to list_objects
                success, file_index = list_objects(
                    target,
                    output_file,
                    max_files_per_bucket,
                    include_types,
                    exclude_types,
                    include_keywords,
                    exclude_keywords,
                    file_index=file_index,
                    download_dir=download_dir,
                    executor=executor,
                    download_timeout=download_timeout,
                    download_retries=download_retries,
                    hits_config=hits_config,
                    raw_bucket=raw,
                )
                if not success:
                    # Try HTTP listing fallbacks for this provider
                    print(f"Boto3 list failed for {raw}; trying HTTP fallbacks")
                    keys = []
                    if provider == 'gcs':
                        keys = http_list_gcs(name, max_files_per_bucket)
                    elif provider == 'azure':
                        keys = http_list_azure(name, max_files_per_bucket)
                    else:
                        # Treat original raw host as candidate for virtual-host listing
                        keys = http_list_s3_host(raw, max_files_per_bucket)

                    for key in keys:
                        if key.endswith('/'):
                            continue
                        if not key_matches_keywords(key, include_keywords, exclude_keywords):
                            continue
                        record_hit(hits_config, raw, key, "http")
                        line = 'File: ' + key + '\n'
                        print('File (http):', key)
                        file_index = write_with_rotation(output_file, line, file_index)
                        if download_dir:
                            local_path = os.path.join(download_dir, name, key)
                            ok = http_download_candidates(provider, name, extra, key, local_path)
                            if not ok:
                                print(f"HTTP download failed for {name}/{key}")
            except Exception as e:
                print(f"Unhandled error on bucket {raw}, skipping. Error: {e}")

            print(f"Finished processing bucket: {raw}")

# Create argument parser
parser = argparse.ArgumentParser(description="Enumerate S3 bucket contents.")
parser.add_argument('-l', '--list', required=True, help='File containing list of buckets (one per line).')
parser.add_argument('-o', '--output', required=True, help='Output file name.')
parser.add_argument('-m', '--max-files', type=int, default=1000, help='Max files to enumerate per bucket.')
parser.add_argument('--include-types', help='Comma-separated list of file extensions to include (e.g., .txt,.jpg)')
parser.add_argument('--exclude-types', help='Comma-separated list of file extensions to exclude (e.g., .log,.tmp)')
parser.add_argument('--download-dir', help='Optional directory to download objects into (creates per-bucket subfolders).')
parser.add_argument('--per-bucket-downloads', type=int, default=DEFAULT_PER_BUCKET_DOWNLOADS, help='Maximum number of files to download per bucket (default 50).')
parser.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help='Number of concurrent download threads (default 8).')
parser.add_argument('--download-timeout', type=int, default=DEFAULT_DOWNLOAD_TIMEOUT, help='Per-download timeout in seconds (default 60).')
parser.add_argument('--download-retries', type=int, default=DEFAULT_DOWNLOAD_RETRIES, help='Number of retries for HTTP downloads (default 2).')
parser.add_argument('--include-keywords', help='Comma-separated list of substrings that must appear in object names (case-insensitive).')
parser.add_argument('--exclude-keywords', help='Comma-separated list of substrings that should be skipped (case-insensitive).')
parser.add_argument('--bucket-include-keywords', help='Comma-separated substrings bucket identifiers must contain (case-insensitive).')
parser.add_argument('--bucket-exclude-keywords', help='Comma-separated substrings that cause bucket identifiers to be skipped (case-insensitive).')
parser.add_argument('--hit-keywords', help='Comma-separated substrings that should be highlighted and logged when seen in object names.')
parser.add_argument('--hit-regex', help='Comma-separated regular expressions that should trigger a hit when matching object names.')
parser.add_argument('--hits-output', help='Optional file to append high-value hits to (defaults to console only).')
parser.add_argument('--profile', choices=['bank'], help='Preset filters for common hunting scenarios (e.g., "bank").')
args = parser.parse_args()

include_types = [ext.strip() for ext in args.include_types.split(',')] if args.include_types else []
exclude_types = [ext.strip() for ext in args.exclude_types.split(',')] if args.exclude_types else []
include_keywords_raw = [kw.strip() for kw in args.include_keywords.split(',')] if args.include_keywords else []
exclude_keywords_raw = [kw.strip() for kw in args.exclude_keywords.split(',')] if args.exclude_keywords else []
bucket_include_raw = [kw.strip() for kw in args.bucket_include_keywords.split(',')] if args.bucket_include_keywords else []
bucket_exclude_raw = [kw.strip() for kw in args.bucket_exclude_keywords.split(',')] if args.bucket_exclude_keywords else []
hit_keywords_raw = [kw.strip() for kw in args.hit_keywords.split(',')] if args.hit_keywords else []
hit_regex_patterns = [pattern.strip() for pattern in args.hit_regex.split(',')] if args.hit_regex else []

BANK_PROFILE = {
    "include_keywords": [
        "bank",
        "account",
        "statement",
        "transaction",
        "wire",
        "ach",
        "routing",
        "swift",
        "iban",
        "card",
        "payment",
        "ledger",
        "customer",
        "balance",
    ],
    "bucket_include_keywords": [
        "bank",
        "card",
        "payment",
        "finance",
        "ach",
        "wire",
        "statement",
        "transaction",
    ],
    "hit_keywords": [
        "account",
        "acct",
        "iban",
        "swift",
        "routing",
        "aba",
        "ach",
        "wire",
        "ledger",
        "balance",
        "statement",
        "customer",
        "deposit",
        "withdraw",
        "sortcode",
    ],
    "hit_regexes": [
        r"\b\d{9}\b",
        r"\b\d{12,19}\b",
        r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    ],
    "exclude_types": [".nc"],
}

profile = args.profile
if profile == 'bank':
    if not include_keywords_raw:
        include_keywords_raw = list(BANK_PROFILE["include_keywords"])
    if not exclude_types:
        exclude_types = list(BANK_PROFILE["exclude_types"])
    if not bucket_include_raw:
        bucket_include_raw = list(BANK_PROFILE["bucket_include_keywords"])
    if not hit_keywords_raw:
        hit_keywords_raw = list(BANK_PROFILE["hit_keywords"])
    if not hit_regex_patterns:
        hit_regex_patterns = list(BANK_PROFILE["hit_regexes"])

include_keywords = [kw.lower() for kw in include_keywords_raw if kw]
exclude_keywords = [kw.lower() for kw in exclude_keywords_raw if kw]
bucket_include_keywords = [kw.lower() for kw in bucket_include_raw if kw]
bucket_exclude_keywords = [kw.lower() for kw in bucket_exclude_raw if kw]
hit_keywords = [kw.lower() for kw in hit_keywords_raw if kw]

hit_regexes = []
for pattern in hit_regex_patterns:
    if not pattern:
        continue
    try:
        hit_regexes.append(re.compile(pattern, re.IGNORECASE))
    except re.error as exc:
        raise SystemExit(f"Invalid hit regex '{pattern}': {exc}") from exc

hits_config = None
if hit_keywords or hit_regexes or args.hits_output:
    hits_config = {
        "keywords": hit_keywords,
        "regexes": hit_regexes,
        "path": args.hits_output,
    }

# Run the script with provided arguments
PER_BUCKET_DOWNLOADS = args.per_bucket_downloads
CONCURRENCY = args.concurrency
DOWNLOAD_TIMEOUT = args.download_timeout
DOWNLOAD_RETRIES = args.download_retries
process_buckets(
    args.list,
    args.output,
    args.max_files,
    include_types,
    exclude_types,
    include_keywords,
    exclude_keywords,
    bucket_include_keywords,
    bucket_exclude_keywords,
    hits_config,
    download_dir=args.download_dir,
)

