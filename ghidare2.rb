require 'r2pipe'
require 'pry'
require 'shellwords'
require 'coderay'

r2p = R2Pipe.new

exec = r2p.cmdj('ij')['core']['file']
offset = r2p.cmdj('sj')[0]['offset']

cmd = "analyzeHeadless . Test.gpr -import #{Shellwords.shellescape exec} -postScript GhidraDecompiler.java #{offset.to_s 16} -deleteProject 2>/dev/null"

`#{cmd}`

`astyle ./decompiled.c`
x = IO.read "./decompiled.c"
puts CodeRay.scan(x, :c).term
