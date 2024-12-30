package ghidrar2web;

import ghidra.program.model.address.Address;

public abstract class R2CmdHandler {
	public abstract boolean canHandle(char cmdChar);
	public abstract String handle(String cmd);
	
	public boolean canHandle(String cmd) {
		return canHandle(cmd.charAt(0));
	}
	
	protected static String hexAddress(Address addr) {
		return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
	}

	protected static String hexAddress(Long addr) {
		return "0x" + String.format("%1$08x", addr);
	}
}
