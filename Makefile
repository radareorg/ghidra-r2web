FCNADDR=1000011e8
TESTBIN=$(shell pwd)/test/ls

all:
	analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript ghidra/GhidraDecompiler.java $(FCNADDR) -deleteProject
	r2 -caf -i ghidra-output.r2 $(TESTBIN)

R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)

install:
	ln -fs $(shell pwd)/r2g $(R2PM_BINDIR)/r2g
