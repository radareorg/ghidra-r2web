package ghidrar2web;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class GhidraR2WebCmdHandler implements HttpHandler {
	static List<R2CmdHandler> handlers = Arrays.asList(new R2HelpCmd(), new R2VersionCmd());
	
	void sendResponse(HttpExchange exchange, byte[] response) throws IOException{
		exchange.sendResponseHeaders(200, response.length);
		OutputStream os = exchange.getResponseBody();
		os.write(response);
		os.close();
	}
	
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		
		String cmd = exchange.getRequestURI().getPath().substring(5);
		for(R2CmdHandler h: handlers) {
			if (h.canHandle(cmd.charAt(0))) {
					byte[] response = h.handle(cmd).getBytes();
					sendResponse(exchange, response);
					return;
			}
		}
		sendResponse(exchange, "Not implemented".getBytes());
	}
}
