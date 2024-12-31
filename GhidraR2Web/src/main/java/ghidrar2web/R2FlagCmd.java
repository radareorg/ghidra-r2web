package ghidrar2web;

public class R2FlagCmd extends R2CmdHandler {

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'f')
			return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		String[] parts = cmd.split(" ");
		if (parts.length > 1) {
			try {
				GhidraR2State.api.start(); // Start transaction
				GhidraR2State.api.createLabel(GhidraR2State.r2Seek, parts[1], false);
				GhidraR2State.api.end(true); // Commit transaction
			} catch (Exception e) {
				GhidraR2State.api.end(false);
				return e.getMessage();
			}
		}
		
		return "";

	}

}
