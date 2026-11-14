"""Verify IDA-derived entity signatures against an exported 70938 PE, without IDA."""
import argparse
import json
from pathlib import Path
import re
import struct

parser=argparse.ArgumentParser()
parser.add_argument('executable',type=Path,help='70938 PE export used by the IDB')
args=parser.parse_args()
profile=json.loads((Path(__file__).resolve().parents[1]/'grid/entity-verification-70938.json').read_text())
raw=args.executable.read_bytes()
assert raw[:2]==b'MZ','not a PE'
nt=struct.unpack_from('<I',raw,60)[0]
assert raw[nt:nt+4]==b'PE\0\0','invalid PE signature'
assert struct.unpack_from('<I',raw,nt+8)[0]==int(profile['timestamp'],16),'different client timestamp'
count=struct.unpack_from('<H',raw,nt+6)[0]
optional=struct.unpack_from('<H',raw,nt+20)[0]
sections=[]
for index in range(count):
    at=nt+24+optional+40*index
    size,rva,raw_size,offset=struct.unpack_from('<IIII',raw,at+8)
    flags=struct.unpack_from('<I',raw,at+36)[0]
    sections.append((rva,raw[offset:offset+raw_size],flags))

def read(rva,size):
    for begin,data,_ in sections:
        if begin<=rva and rva+size<=begin+len(data):return data[rva-begin:rva-begin+size]
    raise ValueError(f'unmapped RVA {rva:#x}')

for binding in profile['bindings']:
    expression=b''.join(b'.' if byte=='??' else re.escape(bytes.fromhex(byte))
                        for byte in binding['pattern'].split())
    hits=[rva+match.start() for rva,data,flags in sections if flags&0x20000000
          for match in re.finditer(expression,data,re.DOTALL)]
    assert len(hits)==1,(binding['name'],hits)
    target=hits[0]
    if 'disp' in binding:
        target+=binding['size']+int.from_bytes(read(hits[0]+binding['disp'],4),'little',signed=True)
    assert target==binding['target'],(binding['name'],hex(target),hex(binding['target']))
assert list(struct.unpack('<15I',read(0x3DF5E80,60)))==profile['type_masks'],'type hierarchy changed'
print(f"Verified {len(profile['bindings'])} unique bindings/RIP targets and all 15 type masks")
