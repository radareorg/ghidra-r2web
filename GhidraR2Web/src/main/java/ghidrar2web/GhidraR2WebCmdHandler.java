package ghidrar2web;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class GhidraR2WebCmdHandler implements HttpHandler {

	// TODO This should be a tree/forest!
	static List<R2CmdHandler> handlers = 
			Arrays.asList(	new R2HelpCmd(), 
							new R2VersionCmd(), 
							new R2SeekCmd(),
							new R2PrintCmd(), 
							new R2InfoCmd(), 
							new R2FlagCmd(), 
							new R2StringSearchCmd(), 
							new R2BlocksizeCmd(),
							new R2CreateCmd(),
							new R2AnalyzeCmd()
						);

	void sendResponse(HttpExchange exchange, byte[] response) throws IOException {
		exchange.sendResponseHeaders(200, response.length);
		OutputStream os = exchange.getResponseBody();
		os.write(response);
		os.close();
	}

	void sendErrorResponse(int status, HttpExchange exchange, byte[] response) throws IOException {
		exchange.sendResponseHeaders(status, response.length);
		OutputStream os = exchange.getResponseBody();
		os.write(response);
		os.close();
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {

		String cmd = exchange.getRequestURI().getQuery();
		if (cmd == null) {
			cmd = exchange.getRequestURI().getPath().substring(5);
		}
		if (cmd != null) {
			for (R2CmdHandler h : handlers) {
				if (h.canHandle(cmd)) {
					byte[] response = h.handle(cmd).getBytes();
					sendResponse(exchange, response);
					return;
				}
			}
		} else {
			sendErrorResponse(400, exchange, "Empty request".getBytes());
		}
		sendErrorResponse(500, exchange, "Not implemented".getBytes());
	}
}
