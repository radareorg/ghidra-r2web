r2ghidra
========

This repository contains integration scripts to interop Ghidra and radare2.

Usage:
------

* make install to get the R2GhidraServer.java installed in the ghidra place
* Start ghidra and doubleclick the script to get the http server
* Attach r2 to the ghidra session

	$ r2 r2web://localhost:8002/cmd

* Run commands into the ghidra server from r2 or the shell

	* \pdd
	* !curl http://localhost:8002/cmd/p8%2080

Other commands may be interesting to have:

	$ curl http://localhost:8002/cmd/afl
	$ curl http://localhost:8002/cmd/pdd
	$ curl http://localhost:8002/cmd/pdd*
	...

I will add curl dependency into r2 to get this to work.


--pancake
