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


--pancake
