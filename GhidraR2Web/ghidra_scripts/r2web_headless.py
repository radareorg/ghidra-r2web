from ghidrar2web import GhidraR2WebServer, GhidraR2State

from ghidra.program.flatapi import FlatProgramAPI

import time

GhidraR2State.api = FlatProgramAPI(currentProgram)
GhidraR2State.r2Seek = GhidraR2State.api.toAddr(0)

GhidraR2WebServer.start(9191)

while True:
    time.sleep(60)
