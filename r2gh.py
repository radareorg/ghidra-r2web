import sys

sys.path.append('/Library/Python/2.7/site-packages/')

import r2pipe

r2 = r2pipe.open("http://localhost:9090")
f = getFirstFunction()
while f is not None:
  _ = r2.cmd("f ghidra." + f.getName() + " = 0x" + str(f.getEntryPoint()))
  f = getFunctionAfter(f)

d = getFirstData()
while d is not None:
  _ = r2.cmd("CC " + str(d) + " @ 0x" + str(d.getAddress()))
  d = getDataAfter(d)

r2.quit()
