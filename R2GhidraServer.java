// Starts an http server to let r2 talk with us
// @author pancake <pancake@nopcode.org>
// @category integration
// @keybinding
// @menupath
// @toolbar
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Base64;

public class R2GhidraServer extends GhidraScript {
  static R2GhidraServer ghidra = null;
  static HttpServer server = null;
  static int blocksize = 128;

  static class MyRootHandler implements HttpHandler {
    public void handle(HttpExchange t) throws IOException {
      try {
        byte[] response = "".getBytes();
        t.sendResponseHeaders(200, response.length);
        OutputStream os = t.getResponseBody();
        os.write(response);
        os.close();
      } catch (Exception e) {
        ghidra.println(e.toString());
      }
    }
  }

  static class MyCmdHandler implements HttpHandler {
    private String cmdAf(String arg) {
      char rad = (arg.indexOf("*") != -1) ? '*' : ' ';
      Function f = ghidra.getFunctionAt(ghidra.currentAddress);
      if (f == null) {
        return "Cannot find function at " + ghidra.currentAddress + "\n";
      }
      try {
        Variable[] vars = f.getAllVariables();
        String comment = f.getComment();
        StringBuffer sb = new StringBuffer();
        Address addr = f.getEntryPoint();
        if (comment != null) {
          String b64comment = Base64.getEncoder().encodeToString(comment.getBytes());
          sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, addr));
        }
        sb.append("?e Done\n");
        return sb.toString();
      } catch (Exception e) {
        return e.toString() + "\n";
      }
    }

    private String cmdPdd(String arg) {
      char rad = (arg.indexOf("*") != -1) ? '*' : ' ';
      Function f = ghidra.getFunctionAt(ghidra.currentAddress);
      try {
        return ghidra.decompile(f, rad);
      } catch (Exception e) {
        return e.toString() + "\n";
      }
    }

    private String showUsage() {
      return "Usage: .\\afl .\\i* \\pdd\n";
    }

    private String cmdPrint8(String arg) {
      int len = Integer.parseInt(arg);
      if (len < 1) {
        len = blocksize;
      }
      StringBuffer sb = new StringBuffer();
      try {
        byte[] bytes = ghidra.getBytes(ghidra.currentAddress, len);
        for (int i = 0; i < bytes.length; i++) {
          String b = Integer.toHexString(0x100 | (int) (bytes[i] & 0xff)).substring(1);
          sb.append(b);
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
        long dec = Long.decode(cmd.substring(tmpAddr + 1));
        String addr = "0x" + Long.toHexString(dec);
        ghidra.currentAddress = ghidra.parseAddress(addr);
        ghidra.goTo(ghidra.currentAddress);
        cmd = cmd.substring(0, tmpAddr);
      }
      ghidra.println("COMMAND: " + cmd);
      if (cmd.length() == 0) {
        return "Unknown r2ghidra command.";
      }
      switch (cmd.charAt(0)) {
        case '/':
          if (cmd.length() > 1) {
            switch (cmd.charAt(1)) {
              case ' ':
                Address[] res = ghidra.findBytes(ghidra.currentAddress, cmd.substring(2), 9999);
                String out = "";
                for (Address a : res) {
                  out += a.toString() + "\n";
                }
                return out;
              case 'x':
                return "Usage: / \\xAA\\xBB instead";
            }
          }
          return "Usage: '/ string' or '/x [hex]'";
        case 'a':
          if (cmd.equals("aa")) {
            Program program = ghidra.getCurrentProgram();
            ghidra.analyzeAll(program);
          } else if (cmd.equals("af")) {
            Address addr = ghidra.currentAddress;
            // ghidra.addEntrypoint(addr);
            ghidra.disassemble(addr);
            ghidra.createFunction(addr, "ghidra." + addr.toString());
          } else if (cmd.startsWith("afl")) {
            boolean rad = cmd.indexOf("*") != -1;
            Function f = ghidra.getFirstFunction();
            StringBuffer sb = new StringBuffer();
            while (f != null) {
              if (rad) {
                sb.append("f ghi." + f.getName() + " 1 0x" + f.getEntryPoint() + "\n");
              } else {
                sb.append("0x" + f.getEntryPoint() + "  " + f.getName() + "\n");
              }
              f = ghidra.getFunctionAfter(f);
            }
            return sb.toString();
          } else if (cmd.equals("af")) {
            return cmdAf(cmd);
          }
          return "See afl";
        case '?':
          switch (cmd.charAt(1)) {
            case 'V':
              return ghidra.getGhidraVersion() + "\n";
            case 'p':
              Address at = null;
              try {
                at = ghidra.currentAddress.getAddress(cmd.substring(2));
              } catch (Exception e) {
              }
              if (at == null) {
                at = ghidra.currentAddress;
              }
              return "0x" + at.getPhysicalAddress() + "\n";
          }
          return showUsage();
        case 'f':
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            try {
              String comment = cmd.substring(2);
              ghidra.createLabel(ghidra.currentAddress, comment, false);
            } catch (Exception e) {
              return e.toString();
            }
            return "";
          }
          return "";
        case 'i':
          // "is"
          // SymbolTable  program.getSymbolTable()
          // "iD"
          // java.lang.String  getDemangled​(java.lang.String mangled)
          if (cmd.equals("is")) {
            return runCommand("afl*");
          }
          Program program = ghidra.getCurrentProgram();
          Language l = program.getLanguage();
          String processor = l.getProcessor().toString().toLowerCase();
          // TODO: incomplete
          String arch = "x86";
          String bits = "64";
          if (processor.equals("aarch64")) {
            arch = "arm";
            bits = "64";
          } else if (processor.indexOf("arm") != -1) {
            arch = "arm";
            bits = "32";
          }
          String res = "e asm.arch=" + arch + "\n";
          res += "e asm.bits=" + bits + "\n";
          res += "f base.addr=0x" + program.getImageBase() + "\n";
          res += "# cpu " + processor + "\n";
          res += "# md5 " + program.getExecutableMD5() + "\n";
          res += "# exe " + program.getExecutablePath() + "\n";
          return res;
        case 'C': // "C"
          try {
            if (cmd.length() > 1) {
              switch (cmd.charAt(1)) {
                case 's': // "Cs"
                  ghidra.createAsciiString(ghidra.currentAddress);
                  break;
                case 'd': // "Cd"
                  ghidra.createWord(ghidra.currentAddress);
                  break;
                case 'C': // "CC"
                  if (cmd.length() > 2 && cmd.charAt(2) == ' ') {
                    ghidra.println("Set comment");
                    ghidra.setPreComment(ghidra.currentAddress, cmd.substring(3));
                    return "";
                  }
                  ghidra.println("List comment");
                  return allComments();
              }
            }
          } catch (Exception e) {
            return e.toString();
          }
          return "Usage: CC [comment] @ addr";
        case 's': // "s"
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            ghidra.goTo(ghidra.parseAddress(cmd.substring(2)));
            return "";
          }
          return "0x" + ghidra.currentAddress.toString() + "\n";
        case 'p':
          if (cmd.length() > 1) {
            switch (cmd.charAt(1)) {
              case 'x': // "px"
                break;
              case '8': // "p8"
                return cmdPrint8(cmd.substring(2).trim());
              case 'd': // "pdd" and "pdd*"
                return cmdPdd(cmd.substring(2).trim());
                // TODO
              default:
                return "Usage: p[x8d]";
            }
          }
          break;
        case 'x': // "x"
          StringBuffer sb = new StringBuffer();
          try {
            byte[] bytes = ghidra.getBytes(ghidra.currentAddress, blocksize);
            for (int i = 0; i < bytes.length; i++) {
              sb.append(" " + bytes[i]);
            }
          } catch (Exception e) {
            sb.append(e.toString());
          }
          return sb.toString() + "\n";
        case 'b':
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            blocksize = Integer.parseInt(cmd.substring(2));
            return "";
          }
          return "" + blocksize + "\n";
        case 'q':
          server.stop(0);
          server = null;
          return "quit";
      }
      return cmd;
    }

    public String allComments() {
      StringBuffer sb = new StringBuffer();
      MemoryBlock[] blocks = ghidra.getMemoryBlocks();

      // iterate through all memory blocks in current program
      for (int i = 0; i < blocks.length; i++) {
        // iterate through all addresses for current block
        MemoryBlock m = blocks[i];
        ghidra.println("Scanning block beginning at 0x" + m.getStart().toString());
        Address a;
        for (a = m.getStart(); !a.equals(m.getEnd().add(1)); a = a.add(1)) {
          String curComment;

          // replace target with replacement within each comment at address
          curComment = ghidra.getEOLComment(a);
          if (curComment != null) {
            sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
            // setEOLComment(a, newComment);
          }
          /*
                    curComment = getPlateComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPlateComment(a, newComment);
                    }
                    curComment = getPostComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPostComment(a, newComment);
                    }
                    curComment = getPreComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPreComment(a, newComment);
                    }
          */
        }
      }
      return sb.toString();
    }

    public void handle(HttpExchange t) throws IOException {
      // query must be urlencoded
      String cmd = t.getRequestURI().getPath().toString().substring(5);
      try {
        byte[] response = runCommand(cmd).getBytes();
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
    String portString = askString("r2web HTTP Server", "Port", "9191");
    int port = Integer.parseInt(portString);
    if (port < 1) {
      port = 9191;
    }
    // port = askInt("r2ghidra webserver", "Port number");
    server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", new MyRootHandler());
    server.createContext("/cmd", new MyCmdHandler());
    server.setExecutor(null); // creates a default executor
    server.start();
    println("Run this line to stop the server: 'curl http://localhost:" + port + "/cmd/q'");
    boolean res =
        askYesNo(
            "Do you want to stop the r2ghidra webserver?",
            "$ r2 r2web://localhost:"
                + port
                + "/cmd/\nPress yes to stop the server.\nPress 'no' to continue in background (EXPERIMENTAL)");
    if (res) {
      // to run in background just comment this line,
      // but if the script is changed we cant shut it
      // down until we close Ghidra completely
      server.stop(0);
    }
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
        codeline = line.getIndentString() + codeline;
      }
      if (rad == '*') {
        String b64comment = Base64.getEncoder().encodeToString(codeline.getBytes());
        sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
      } else {
        if (maxAddress == 0) {
          String msg = String.format("           %s\n", codeline);
          sb.append(msg);
        } else {
          String msg = String.format("0x%-8x %s\n", minAddress, codeline);
          sb.append(msg);
        }
      }
    }
    return sb.toString();
  }
}
