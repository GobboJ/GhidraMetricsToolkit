//Computes the Halstead metrics of a function and the entire program
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import impl.Halstead;
import impl.utils.CsvExporter;

import java.io.IOException;
import java.util.List;


public class HalsteadScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        String csvPath = null;
        String[] args = getScriptArgs();
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--csv-export")) {
                if (args.length > i + 1 && !args[i + 1].startsWith("--")) {
                    csvPath = args[i + 1];
                }
            }
        }

        Function currentFunction = currentProgram.getFunctionManager().getFunctionAt(currentAddress);
        Halstead halstead = new Halstead(currentProgram, currentFunction);
        Halstead.Result result = (Halstead.Result) halstead.compute();
        printf(result.toString());

        if (csvPath != null) {
            try {
                List<Pair<String, String>> out = result.export();
                Pair<String, String> programHalstead = out.getFirst();
                CsvExporter csvExporter = new CsvExporter(csvPath, programHalstead.first);
                csvExporter.exportData(programHalstead.second);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
