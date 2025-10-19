import argparse
import boto3
import os
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError

# Initialize S3 client with unsigned requests
s3_client = boto3.client("s3", config=Config(signature_version=UNSIGNED))

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

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

def list_objects(bucket, output_file, max_files, include_types, exclude_types, prefix='', delimiter='', continuation_token=None, file_index=1):
    """
    List objects in an S3 bucket up to a specified maximum number of files.
    """
    kwargs = {
        'Bucket': bucket,
        'Prefix': prefix,
        'Delimiter': delimiter,
        'MaxKeys': 100000
    }

    if continuation_token:
        kwargs['ContinuationToken'] = continuation_token

    try:
        response = s3_client.list_objects_v2(**kwargs)
    except ClientError as e:
        print(f"Error accessing bucket '{bucket}': {e}")
        return False, file_index

    file_count = 0

    for obj in response.get('Contents', []):
        key = obj['Key']
        if include_types and not any(key.endswith(ext) for ext in include_types):
            continue
        if exclude_types and any(key.endswith(ext) for ext in exclude_types):
            continue

        if file_count >= max_files:
            return False, file_index

        line = 'File: ' + key + '\n'
        print('File:', key)
        file_index = write_with_rotation(output_file, line, file_index)
        file_count += 1

    for common_prefix in response.get('CommonPrefixes', []):
        line = 'Folder: ' + common_prefix['Prefix'] + '\n'
        print('Folder:', common_prefix['Prefix'])
        file_index = write_with_rotation(output_file, line, file_index)

    if response.get('IsTruncated') and file_count < max_files:
        return list_objects(bucket, output_file, max_files - file_count, include_types, exclude_types, prefix, delimiter, response.get('NextContinuationToken'), file_index)

    return True, file_index

def process_buckets(bucket_list_file, output_file, max_files_per_bucket, include_types, exclude_types):
    """
    Process multiple buckets listed in a text file.
    """
    with open(bucket_list_file, 'r') as file:
        buckets = [line.strip() for line in file.readlines()]

    file_index = 1
    for bucket in buckets:
        print(f"Processing bucket: {bucket}")
        header = f"\n--- Bucket: {bucket} ---\n"
        file_index = write_with_rotation(output_file, header, file_index)

        try:
            success, file_index = list_objects(bucket, output_file, max_files_per_bucket, include_types, exclude_types, file_index=file_index)
            if not success:
                print(f"Limit reached or error while processing bucket: {bucket}")
        except Exception as e:
            print(f"Unhandled error on bucket {bucket}, skipping. Error: {e}")

        print(f"Finished processing bucket: {bucket}")

# Create argument parser
parser = argparse.ArgumentParser(description="Enumerate S3 bucket contents.")
parser.add_argument('-l', '--list', required=True, help='File containing list of buckets (one per line).')
parser.add_argument('-o', '--output', required=True, help='Output file name.')
parser.add_argument('-m', '--max-files', type=int, default=1000, help='Max files to enumerate per bucket.')
parser.add_argument('--include-types', help='Comma-separated list of file extensions to include (e.g., .txt,.jpg)')
parser.add_argument('--exclude-types', help='Comma-separated list of file extensions to exclude (e.g., .log,.tmp)')
args = parser.parse_args()

include_types = [ext.strip() for ext in args.include_types.split(',')] if args.include_types else []
exclude_types = [ext.strip() for ext in args.exclude_types.split(',')] if args.exclude_types else []

# Run the script with provided arguments
process_buckets(args.list, args.output, args.max_files, include_types, exclude_types)
