#!/usr/bin/env python3
import sys

def emit(name, path):
    d = open(path, 'rb').read()
    sym = name.replace('.', '_').replace('-', '_')
    L = ['const unsigned char %s_start[] = {' % sym]
    L.append(','.join(str(b) for b in d))
    L.append('};')
    L.append('const unsigned long %s_len = %d;' % (sym, len(d)))
    return '\n'.join(L)

*kos, sh, out = sys.argv[1:]
short = {}
for k in kos:
    base = k.split('rwbridge-')[1].rsplit('.ko', 1)[0]
    short[base] = base.replace('-', '_').replace('.', '_')
parts = [emit('_binary_rwbridge_' + short[k.split('rwbridge-')[1].rsplit('.ko', 1)[0]] + '_ko', k)
         for k in kos]
parts.append(emit('_binary_runsh', sh))
open(out, 'w').write('\n'.join(parts) + '\n')
print(f'blobs written: universal + {len(kos)} artifacts + run.sh')