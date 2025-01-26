//Computes the McCabe cyclomatic complexity of the whole program
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import impl.McCabe;
import impl.common.ResultInterface;
import impl.utils.CsvExporter;

import java.io.IOException;
import java.util.List;


public class McCabeScript extends GhidraScript {

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

        McCabe complexity = new McCabe(currentProgram);
        ResultInterface result = complexity.compute();
        println("Complexity: " + result);

        if (csvPath != null) {
            try {
                List<Pair<String, String>> out = result.export();
                Pair<String, String> binaryResult = out.getFirst();
                CsvExporter csvExporter = new CsvExporter(csvPath, binaryResult.first);
                csvExporter.exportData(binaryResult.second);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
