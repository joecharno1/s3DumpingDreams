import sys
from pathlib import Path

IN = Path('buckets.txt')
OUT = Path('subset100.txt')

def is_valid(raw: str) -> bool:
    if not raw or not raw.strip():
        return False
    r = raw.strip()
    if ' ' in r or '(' in r or ')' in r or '*' in r:
        return False
    if r.startswith('-'):
        return False
    if r.lower() == 'text' or len(r) < 2:
        return False
    return True

def make_subset(n=100):
    if not IN.exists():
        print('buckets.txt not found')
        return 1
    out_lines = []
    with IN.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if is_valid(line):
                out_lines.append(line)
                if len(out_lines) >= n:
                    break
    with OUT.open('w', encoding='utf-8') as f:
        for l in out_lines:
            f.write(l + '\n')
    print(f'Wrote {len(out_lines)} lines to {OUT}')
    return 0

if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    raise SystemExit(make_subset(n))
