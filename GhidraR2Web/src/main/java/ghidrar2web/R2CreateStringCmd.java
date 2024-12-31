package ghidrar2web;

public class R2CreateStringCmd extends R2CmdHandler {
	public R2CreateStringCmd(){
		this(0);
	}
	public R2CreateStringCmd(int pos){
		cmdPos = pos;
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 's') return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		try {
        	GhidraR2State.api.start();
			GhidraR2State.api.createAsciiString(GhidraR2State.r2Seek);
			GhidraR2State.api.end(true);
			return "";
        } catch (Exception e) {
			GhidraR2State.api.end(false);
			return e.getMessage();
		}
	}

}
