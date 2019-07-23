r2ghidra
========

This repository contains integration scripts to interop Ghidra and radare2.

The r2ghidraserver is a Ghidra plugin that starts an http server to let r2 talk to it.

Features
--------

* Decompile current function
* Load the decompiler output as comments
* List functions found by Ghidra ('afl')
* List symbols 'is' from Ghidra bin parser
* Import comments from Ghidra into r2
* Read/Write ghidra's session remote memory contents

Usage
-----

* Install Ghidra using r2pm

	$ r2pm -i ghidra

* Symlink the R2GhidraServer.java into the ghidra plugins directory

	$ make install

* Start ghidra and doubleclick the script to get the http server

	$ r2pm -r ghidraRun

* Attach r2 to the ghidra session

	$ r2 r2web://localhost:8002/cmd

* Run commands into the ghidra server from r2 or the shell

	* \pdd
	* !curl http://localhost:8002/cmd/p8%2080

Available commands (via curl or r2web)

* afl
* i
* is
* CC
* s
* px, p8, pd
* b - blocksize
* q

--pancake
