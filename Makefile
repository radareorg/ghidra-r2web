FCNADDR=1000011e8
TESTBIN=$(shell pwd)/test/ls

all:
	analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript GhidraDecompiler.java $(FCNADDR) -deleteProject
	r2 -caf -i ghidra-output.r2 $(TESTBIN)

R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)

install:
	ln -fs $(shell pwd)/r2g $(R2PM_BINDIR)/r2g

GJF=google-java-format-1.7-all-deps.jar

$(GJF):
	wget https://github.com/google/google-java-format/releases/download/google-java-format-1.7/google-java-format-1.7-all-deps.jar

indent: $(GJF)
	java -jar $(GJF) -i *.java */*.java
