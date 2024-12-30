package ghidrar2web;

public class R2PrintHexCmd extends R2CmdHandler {

	@Override
	public boolean canHandle(char cmdChar) {
		// TODO Auto-generated method stub
		return false;
	}
	
	public boolean canHandle(String cmd) {
		if (cmd.startsWith("px")) return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		// TODO Auto-generated method stub
		return "";
	}

}
