package ghidrar2web;

import java.util.Arrays;
import java.util.List;

public class R2PrintCmd extends R2CmdHandler {
	List<R2CmdHandler> handlers = Arrays.asList(new R2PddCmd(), new R2P8Cmd(), new R2PrintHexCmd());
	@Override
	public boolean canHandle(char cmdChar) {
		return false;
	}
	
	private R2CmdHandler findHandler(String cmd) {
		for (R2CmdHandler h: handlers) {
			if (h.canHandle(cmd)) {
				return h;
			}
		}
		return null;
	}
	@Override
	public boolean canHandle(String cmd) {
		if (cmd.charAt(0) != 'p') return false;
		R2CmdHandler h = findHandler(cmd);
		if (h == null) {
			return false;
		}
		return true;
	}

	@Override
	public String handle(String cmd) {
		R2CmdHandler h = findHandler(cmd);
		if (h == null) {
			return "Subhandler not found!";
		}
		
		return h.handle(cmd);
	}

}
