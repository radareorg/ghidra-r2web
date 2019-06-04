//Starts an http server to let r2 talk with us
//@author pancake <pancake@nopcode.org>
//@category integration
//@keybinding 
//@menupath 
//@toolbar 
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.util.headless.HeadlessScript;
import java.util.Base64;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class R2GhidraServer extends GhidraScript {
  static R2GhidraServer ghidra = null;
  static HttpServer server = null;
  static int blocksize = 128;

  static class MyCmdHandler implements HttpHandler {
    private String cmdPdd(String arg) {
      char rad = arg.charAt(0); // handle "pdd, pdd*, .."
      Function f = ghidra.getFunctionAt(ghidra.currentAddress);
      try {
        return ghidra.decompile(f, rad);
      } catch (Exception e) {
        return e.toString() + "\n";
      }
    }
    private String cmdPrint8(String arg) {
      int len = Integer.parseInt(arg);
      if (len < 1) {
        len = blocksize;
      } else {
        len *= 4; // wtf ? :D
      }
      StringBuffer sb = new StringBuffer();
      try{
        byte [] bytes = ghidra.getBytes(ghidra.currentAddress, len);
        for (int i = 0; i < bytes.length; i++) {
          String b = Integer.toHexString(0x100 | (int)(bytes[i] & 0xff)).substring(1);
          sb.append (b);
        }
      } catch (Exception e) {
        sb.append(e.toString());
      }
      return sb.toString() + "\n";
    }
    String runCommand(String cmd) {
      int tmpAddr = cmd.indexOf('@');
      if (tmpAddr != -1) {
        Address origAddress = ghidra.currentAddress;
        long dec = Long.parseLong(cmd.substring(tmpAddr + 1));
        String addr = "0x" + Long.toHexString(dec);
        ghidra.currentAddress = ghidra.parseAddress(addr);
        ghidra.goTo(ghidra.currentAddress);
        cmd = cmd.substring(0, tmpAddr - 1);
      }
      ghidra.println("COMMAND: " + cmd);
      if (cmd.length() == 0) {
        return "";
      }
      switch (cmd.charAt(0)) {
        case 'a':
          if (cmd.startsWith("afl")) {
            Function f = ghidra.getFirstFunction();
            StringBuffer sb = new StringBuffer();
            while (f != null) {
              sb.append("0x" + f.getEntryPoint() + "  " + f.getName() + "\n");
              f = ghidra.getFunctionAfter(f);
            }
            return sb.toString();
          }
          return "See afl";
        case '?':
          // "?V"
          String str = ghidra.getGhidraVersion();
          return str;
        case 'i':
          // "is"
          // SymbolTable  program.getSymbolTable()
          // "iD"
          // java.lang.String  getDemangled​(java.lang.String mangled)
          Program program = ghidra.getCurrentProgram();
          Language l = program.getLanguage();
          String res = "e asm.arch=" + l.getProcessor().toString().toLowerCase() + "\n";
          res += "f base.addr=0x"+ program.getImageBase() + "\n";
          res += "# md5 " + program.getExecutableMD5() + "\n";
          res += "# exe " + program.getExecutablePath() + "\n";
          return res;
        case 's':
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            ghidra.goTo(ghidra.parseAddress(cmd.substring(2)));
            return "ok\n";
          }
          return "0x" + ghidra.currentAddress.toString() + "\n";
        case 'p':
          switch (cmd.charAt(1)) {
            case 'x':
              break;
            case '8':
              return cmdPrint8(cmd.substring(2).trim());
            case 'd': // "pdd"
              return cmdPdd(cmd.substring(2).trim()); 
              // TODO
          }
          break;
        case 'x':
          StringBuffer sb = new StringBuffer();
          try{
            byte [] bytes = ghidra.getBytes(ghidra.currentAddress, blocksize);
            for (int i = 0; i < bytes.length; i++) {
              sb.append (" " + bytes[i]);
            }
          } catch (Exception e) {
            sb.append(e.toString());
          }
          return sb.toString() + "\n";
        case 'b':
          return "" + blocksize + "\n";
        case 'q':
          server.stop (0);
          server = null;
          return "quit";
      }
      return cmd;
    }
    public void handle(HttpExchange t) throws IOException {
      // query must be urlencoded
      String cmd = t.getRequestURI().getPath().toString().substring(5);
      try {
        byte [] response = runCommand(cmd).getBytes();
        t.sendResponseHeaders(200, response.length);
        OutputStream os = t.getResponseBody();
        os.write(response);
        os.close();
      } catch (Exception e) {
        ghidra.println(e.toString());
      }
    }
  }
  public void run() throws Exception {
    this.ghidra = this;
    int port = 8002;
    // port = askInt("r2ghidra webserver", "Port number");
    server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/cmd", new MyCmdHandler());
    server.setExecutor(null); // creates a default executor
    server.start();
    println("Run this line to stop the server: 'curl http://localhost:"+port+"/cmd/q'");
    askYesNo("r2ghidra webserver running at port 8001", "Press any button to stop it");
    // to run in background just comment this line, but if the script is changed we cant shut it down until we close Ghidra completely
    server.stop(0);
  }

  public String decompile(Function f, char rad) throws Exception {
    StringBuffer sb = new StringBuffer();

    // Stop after this headless script
    // setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    DecompInterface di = new DecompInterface();
    println("Simplification style: " + di.getSimplificationStyle()); // DEBUG
    println("Debug enables: " + di.debugEnabled());

    println(String.format("Decompiling %s() at 0x%s", f.getName(), f.getEntryPoint().toString()));

    println("Program: " + di.openProgram(f.getProgram())); // DEBUG

    // Decompile with a 5-seconds timeout
    DecompileResults dr = di.decompileFunction(f, 5, null);
    println("Decompilation completed: " + dr.decompileCompleted()); // DEBUG

    DecompiledFunction df = dr.getDecompiledFunction();
    println(df.getC());

    // Print lines prepend with addresses
    PrettyPrinter pp = new PrettyPrinter(f, dr.getCCodeMarkup());
    ArrayList<ClangLine> lines = pp.getLines();

    for (ClangLine line : lines) {
      long minAddress = Long.MAX_VALUE;
      long maxAddress = 0;
      for (int i = 0; i < line.getNumTokens(); i++) {
        if (line.getToken(i).getMinAddress() == null) {
          continue;
        }
        long addr = line.getToken(i).getMinAddress().getOffset();
        minAddress = addr < minAddress ? addr : minAddress;
        maxAddress = addr > maxAddress ? addr : maxAddress;
      }
      String codeline = line.toString();
      int colon = codeline.indexOf(':');
      if (colon != -1) {
        codeline = codeline.substring(colon + 1);
        codeline=line.getIndentString() + codeline;
      }
      if (rad == '*') {
        String b64comment = Base64.getEncoder().encodeToString(codeline.getBytes());
        sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
      } else {
        if (maxAddress == 0) {
          String msg = String.format("           %s\n", codeline);
          sb.append (msg);
        } else {
          String msg = String.format("0x%-8x %s\n", minAddress, codeline);
          sb.append (msg);
        }
      }
    }
    return sb.toString();
  }
}
