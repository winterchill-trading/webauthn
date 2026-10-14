# Extract section 16 "Test Vectors" of the WebAuthn Level 3 draft into JSON files.
# Usage: python3 scripts/w3c_vectors.py webauthn-3.html test/vectors/w3c
import sys, re, html, json, os
src, out = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()
i = s.find('id="sctn-test-vectors"')
j = s.find('<section', i + 1000)
ids = re.findall(r'id="(sctn-test-vectors-[A-Za-z0-9-]+)"', s[i:])
os.makedirs(out, exist_ok=True)
def text(a, b):
    return html.unescape(re.sub(r'<[^>]*>', '', s[a:b]))
pos = [(sid, s.find('id="%s"' % sid)) for sid in ids]
for k, (sid, p) in enumerate(pos):
    if sid.endswith('root-cert'):
        continue
    end = pos[k + 1][1] if k + 1 < len(pos) else min(x for x in (s.find('<h3', p + 10), s.find('<h2', p + 10)) if x > 0)
    t = text(p, end)
    title = t.split('\n')[0].split('>', 1)[-1].strip()
    parts = re.split(r'\n\s*Authentication:\s*\n', t)
    def fields(chunk):
        d = {}
        for m in re.finditer(r"^\s*([A-Za-z_]+) = h'([0-9a-f]*)'", chunk, re.M):
            d[m.group(1)] = m.group(2)
        return d
    reg = fields(parts[0]); auth = fields(parts[1]) if len(parts) > 1 else {}
    name = sid[len('sctn-test-vectors-'):]
    json.dump({'section': title, 'rp_id': 'example.org', 'origin': 'https://example.org',
               'top_origin': 'https://example.com', 'registration': reg, 'authentication': auth},
              open(os.path.join(out, name + '.json'), 'w'), indent=1)
    print(name, title, sorted(reg), sorted(auth))
