package ghidrar2web;

import ghidra.program.model.address.Address;

public abstract class R2CmdHandler {
	protected int cmdPos=0;
	
	public abstract boolean canHandle(char cmdChar);
	public abstract String handle(String cmd);

	
	/*public R2CmdHandler setPos(int pos){
		cmdPos=pos;
		return this;
	}*/
	
	public boolean canHandle(String cmd) {
		return canHandle(cmd.charAt(cmdPos));
	}
	
	protected static String hexAddress(Address addr) {
		return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
	}

	protected static String hexAddress(Long addr) {
		return "0x" + String.format("%1$08x", addr);
	}
}
