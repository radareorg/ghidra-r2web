package ghidrar2web;

public class R2BlocksizeCmd extends R2CmdHandler {

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'b') return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		String[] parts = cmd.split(" ");
		if (parts.length > 1) {
			Integer size=Integer.parseInt(parts[1]);
			GhidraR2State.blockSize=size.intValue();
		}
		return Integer.valueOf(GhidraR2State.blockSize).toString();
	}

}
