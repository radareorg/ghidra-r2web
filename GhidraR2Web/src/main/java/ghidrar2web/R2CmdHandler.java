package ghidrar2web;

public abstract class R2CmdHandler {
	public abstract boolean canHandle(char cmdChar);
	public abstract String handle(String cmd);
}
