// Copyright (C) 2019 Guillaume Valadon <guillaume@valadon.net>
// This program is published under a GPLv2 license

/*
 * Decompile a function with Ghidra
 *
 * analyzeHeadless . Test.gpr -import $BINARY_NAME -postScript GhidraDecompiler.java $FUNCTION_ADDRESS -deleteProject -noanalysis
 *
 */

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Base64;

public class GhidraDecompiler extends HeadlessScript {

  @Override
  public void run() throws Exception {
    FileWriter fw = new FileWriter("ghidra-output.r2");
    FileWriter fw_dec = new FileWriter("decompiled.c");

    // Stop after this headless script
    setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    // Get the function address from the script arguments
    String[] args = getScriptArgs();
    println(String.format("Array length: %d", args.length)); // DEBUG

    if (args.length == 0) {
      System.err.println("Please specify a function address!");
      System.err.println("Note: use c0ffe instead of 0xcoffee");
      return;
    }

    long functionAddress = 0;
    try {
      if (args[0].startsWith("0x")) {
        functionAddress = Long.parseLong(args[0].substring(2), 16);
      } else {
        functionAddress = Long.parseLong(args[0], 16);
      }
    } catch (NumberFormatException e) {
      System.err.println(args[0] + " " + e.toString());
    }
    println(String.format("Address: %x", functionAddress)); // DEBUG

    DecompInterface di = new DecompInterface();
    println("Simplification style: " + di.getSimplificationStyle()); // DEBUG
    println("Debug enables: " + di.debugEnabled());

    Function f = this.getFunction(functionAddress);
    if (f == null) {
      System.err.println(String.format("Function not found at 0x%x", functionAddress));
      return;
    }

    println(String.format("Decompiling %s() at 0x%x", f.getName(), functionAddress));

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
      if (maxAddress == 0) {
        println(String.format("                      - %s", line.toString()));
        String comment = line.toString().split(":", 2)[1];
        fw_dec.write(String.format("%s\n", comment));
      } else {
        println(String.format("0x%-8x 0x%-8x - %s", minAddress, maxAddress, line.toString()));
        try {
          String comment = line.toString().split(":", 2)[1];
          System.out.println(comment);
          String b64comment = Base64.getEncoder().encodeToString(comment.getBytes());
          fw.write(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
          fw_dec.write(String.format("%s\n", comment));
        } catch (Exception e) {
          System.out.println("ERROR: " + line.toString());
        }
        // 0x%-8x 0x%-8x - %s", minAddress, maxAddress, line.toString()));
      }
    }
    fw.close();
    fw_dec.close();
  }

  protected Function getFunction(long address) {
    // Logic from https://github.com/cea-sec/Sibyl/blob/master/ext/ghidra/ExportFunction.java

    Listing listing = currentProgram.getListing();
    FunctionIterator iter = listing.getFunctions(true);
    while (iter.hasNext() && !monitor.isCancelled()) {
      Function f = iter.next();
      if (f.isExternal()) {
        continue;
      }

      Address entry = f.getEntryPoint();
      if (entry != null && entry.getOffset() == address) {
        return f;
      }
    }
    return null;
  }
}
