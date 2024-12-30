package ghidrar2web;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;


public class GhidraR2WebServer {
	HttpServer server;
	static GhidraR2WebServer instance;

	static class MyRootHandler implements HttpHandler {
		public void handle(HttpExchange t) throws IOException {

			byte[] response = "Hola".getBytes();
			t.sendResponseHeaders(200, response.length);
			OutputStream os = t.getResponseBody();
			os.write(response);
			os.close();

		}
	}
	
	public static GhidraR2WebServer getInstance(int port) throws IOException {
		if (instance == null) {
			instance = new GhidraR2WebServer(port);
		}
		return instance;
	}

	GhidraR2WebServer(int port) throws IOException {
		server = HttpServer.create(new InetSocketAddress(port), 0);
		server.createContext("/", new MyRootHandler());
		server.createContext("/cmd", new GhidraR2WebCmdHandler());
		server.setExecutor(null); // creates a default executor
		server.start();
	}

	public void stop() {
		this.server.stop(0);
		this.server = null;
	}
}
