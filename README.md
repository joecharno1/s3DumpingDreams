# s3DumpingDreams

## Grayhat Warfare bucket sync

Use `grayhat_fetch.py` to pull the latest public bucket names from
[Grayhat Warfare](https://buckets.grayhatwarfare.com/) and merge them into the
local `buckets.txt` file.

```
python grayhat_fetch.py --api-key $GRAYHAT_API_KEY --pages 5 --dedupe \
    --output buckets.txt --java-target src/main/java/GrayhatBuckets.java
```

Key options:

- `--api-key` (or `GRAYHAT_API_KEY` env var) supplies your Grayhat API token.
- `--pages` / `--page-size` control how many results are downloaded.
- `--dedupe` prevents duplicate entries when merging with the existing list.
- `--java-target` writes the aggregate list to a Java helper class for easy
  consumption in JVM tooling.

Setting the API key
-------------------

You can provide `GRAYHAT_API_KEY` either via the `--api-key` flag or by
setting the `GRAYHAT_API_KEY` environment variable. For convenience during
development you may create a `.env` file in the repository root with a line
like::

  GRAYHAT_API_KEY=your_api_key_here

The repository includes `.env.example` as a template. `.env` is ignored by
git (see `.gitignore`) so your secret won't be committed.

On Windows PowerShell you can also set the variable for the current session::

  $env:GRAYHAT_API_KEY = "your_api_key_here"

## Targeted object downloads

Use `s4.py` to enumerate and optionally download public objects from the bucket
list. To keep noisy datasets (like NOAA GOES NetCDF imagery) out of the output,
combine the existing extension filters with the new keyword filters.

```
python s4.py --list subset100.txt --output focused_results.txt ^
    --exclude-types .nc --include-keywords bank,statement,payment,wire ^
    --download-dir downloads_finance
```

Key options:

- `--include-types` / `--exclude-types` gate objects by file extension.
- `--include-keywords` keeps only keys containing any of the provided substrings
  (case-insensitive).
- `--exclude-keywords` skips keys containing the provided substrings.
- `--bucket-include-keywords` / `--bucket-exclude-keywords` prune the bucket
  list itself before enumeration.
- `--hit-keywords`, `--hit-regex`, and `--hits-output` capture a reduced "hits"
  log when filenames look interesting (useful for spotting credentials or
  account numbers without reading the entire listing).
- `--profile bank` preloads a finance-oriented bundle of filters (object
  keywords, bucket keywords, hit regexes, and a default `.nc` exclusion).

Keyword filtering happens before logging or downloading, so unwanted objects are
ignored entirely.

For example, to focus on finance-sounding buckets, skip GOES imagery, and log
potential hits to `bank_hits.txt`:

```
python s4.py --list subset_finance.txt --output bank_scan.txt ^
    --profile bank --hits-output bank_hits.txt --download-dir downloads_bank ^
    --max-files 200 --per-bucket-downloads 5
```

