#!/usr/bin/env python3
import json, os, sys

matrix = json.loads(os.environ['MATRIX'])
kos = []
for job in matrix['include']:
    kmi = job['kmi']
    if kmi.startswith('universal'):
        continue
    kos.append(f'dl/kmod/rwbridge-{kmi}.ko')
kos.sort()
with open('/tmp/ko_list.txt', 'w') as f:
    f.write(' '.join(kos))
print('KOs to pack:', kos)