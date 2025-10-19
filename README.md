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
