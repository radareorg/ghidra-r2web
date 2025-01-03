GHIDRA_INSTALL_DIR?=$(HOME)/Downloads/$(shell ls -rt ~/Downloads | grep ghidra_ | tail -n 1)

ifeq ($(GHIDRA_INSTALL_DIR),)
all:
	@echo Cannot find Ghidra in ~/Downloads or GHIDRA_INSTALL_DIR

else
all:
	export GHIDRA_INSTALL_DIR=$(GHIDRA_INSTALL_DIR) ; \
	gradle buildExtension
endif
