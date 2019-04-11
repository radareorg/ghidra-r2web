FCNADDR=1000011e8
TESTBIN=$(shell pwd)/test/ls

all:
	#analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript GhidraDecompiler.java $(FCNADDR) -deleteProject -noanalysis
	analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript GhidraDecompiler.java $(FCNADDR) -deleteProject
	r2 -caf -i ghidra-output.r2 /bin/ls
