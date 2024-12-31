package ghidrar2web;

public class R2PrintHexCmd extends R2CmdHandler {

	public R2PrintHexCmd(int i) {
		cmdPos=i;
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if(cmdChar == 'x') return true;
		return false;
	}
	

	@Override
	public String handle(String cmd) {
		// TODO Auto-generated method stub
		return "px not implemented\n";
	}

}
