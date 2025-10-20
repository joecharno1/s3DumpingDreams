# s3DumpingDreams

## Grayhat Warfare bucket sync

Use `grayhat_fetch_runner.py` for a zero-configuration pull of the latest public
bucket names from [Grayhat Warfare](https://buckets.grayhatwarfare.com/) and to
merge them into the local `buckets.txt` file.

```
python grayhat_fetch_runner.py --pages 5 --dedupe \
    --output buckets.txt --java-target src/main/java/GrayhatBuckets.java
```

The runner seeds the `GRAYHAT_API_KEY` environment variable with a working
token. If you want to override the credentials or call the lower-level tool
directly, run `grayhat_fetch.py` with your own export:

```
export GRAYHAT_API_KEY="your_token_here"
python grayhat_fetch.py --pages 5 --dedupe \
    --output buckets.txt --java-target src/main/java/GrayhatBuckets.java
```

Key options:

- `--api-key` (or `GRAYHAT_API_KEY` env var) supplies your Grayhat API token.
- `--pages` / `--page-size` control how many results are downloaded.
- `--dedupe` prevents duplicate entries when merging with the existing list.
- `--java-target` writes the aggregate list to a Java helper class for easy
  consumption in JVM tooling.
