package ghidrar2web;

public class R2SeekCmd extends R2CmdHandler {

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 's') return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		
		String[] parts=cmd.split(" ");
		if (parts.length > 1) {
			GhidraR2State.r2Seek=GhidraR2State.api.toAddr(parts[1]);
		}
		
		return hexAddress(GhidraR2State.r2Seek)+"\n";
	}

}
