from pathlib import Path
import struct,re
class PE:
 def __init__(self,path):
  self.b=Path(path).read_bytes(); nt=struct.unpack_from('<I',self.b,60)[0];n=struct.unpack_from('<H',self.b,nt+6)[0];opt=struct.unpack_from('<H',self.b,nt+20)[0];self.timestamp=struct.unpack_from('<I',self.b,nt+8)[0];self.image_size=struct.unpack_from('<I',self.b,nt+24+56)[0];self.sections=[]
  for i in range(n):
   o=nt+24+opt+i*40;vs,rva,size,raw=struct.unpack_from('<IIII',self.b,o+8);f=struct.unpack_from('<I',self.b,o+36)[0];self.sections.append((rva,self.b[raw:raw+size],f))
 def data(self,a,n):
  for r,d,f in self.sections:
   if r<=a<r+len(d):return d[a-r:a-r+n]
  raise ValueError(hex(a))
 def find(self,p):
  rx=b''.join(b'.' if x=='??' else re.escape(bytes.fromhex(x)) for x in p.split());return [r+m.start() for r,d,f in self.sections if f&0x20000000 for m in re.finditer(rx,d,re.DOTALL)]
new=PE(r'C:\Users\DELTA\Documents\GitHub\binary analysis\Wow 1.60.1.70938.exe')
old=PE(r'C:\Users\DELTA\Documents\GitHub\binary analysis\Wow 1.60.1.70888.exe')
