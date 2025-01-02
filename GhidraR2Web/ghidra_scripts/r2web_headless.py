from ghidrar2web import GhidraR2WebServer, GhidraR2State

from ghidra.program.flatapi import FlatProgramAPI

import os
import time

GhidraR2State.api = FlatProgramAPI(currentProgram)
GhidraR2State.r2Seek = GhidraR2State.api.toAddr(0)

port=9191
if "R2WEB_PORT" in os.environ:
    port=int(os.environ["R2WEB_PORT"])

print("R2WEB Starting r2web on port %d" % (port))
GhidraR2WebServer.start(port)

# TODO We'll need a HTTP server like Jetty to properly wait() for server stop
while True:
    user_input=raw_input("R2WEB E(x)it? ")
    if user_input == 'x':
        GhidraR2WebServer.stop()
        break

