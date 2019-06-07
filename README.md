r2ghidra
========

This repository contains integration scripts to interop Ghidra and radare2.

Usage:
------

Assuming you have r2 from git installed, type:

	$ make install

In one terminal run the following command:

	$ r2g server /bin/ls

Now in the second terminal run r2:

	$ r2 /bin/ls
	[0x080000402]> .!r2g r2

But this is broken because the way r2 http.get works try this:

	$ curl http://localhost:8002/cmd/pi%2080
	$ curl http://localhost:8002/cmd/afl
	$ curl http://localhost:8002/cmd/pdd
	$ curl http://localhost:8002/cmd/pdd*
	...

May be good to add curl as optional dependency to r2 builds i think


--pancake
