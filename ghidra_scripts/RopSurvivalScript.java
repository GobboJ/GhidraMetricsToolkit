//Computes the ROP Survival metrics between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.RopSurvival;
import impl.utils.CsvExporter;
import utils.ProjectUtils;

import java.io.IOException;
import java.util.List;

public class RopSurvivalScript extends GhidraScript {

    private static int DEPTH = 10;

    @Override
    protected void run() throws Exception {

        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        String csvPath = null;

        Program p2;
        if (isRunningHeadless()) {
            String[] args = getScriptArgs();

            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("--csv-export")) {
                    if (args.length > i + 1 && !args[i + 1].startsWith("--")) {
                        csvPath = args[i + 1];
                    }
                }
            }
            if (args.length < 1) {
                printerr("At least one parameter expected");
                return;
            }
            String programName = args[0];
            p2 = ProjectUtils.getProgramByName(state.getProject(), programName);
        } else {
            p2 = askProgram("Pick second program");
        }

        RopSurvival ropSurvival = new RopSurvival(currentProgram, p2, DEPTH);
        RopSurvival.Result result = (RopSurvival.Result) ropSurvival.compute();

        if (result == null) {
            printerr("The programs have different processors. Aborting");
            return;
        }
        printf(result.toString());

        if (csvPath != null) {
            try {
                List<Pair<String, String>> out = result.export();
                Pair<String, String> ropResult = out.getFirst();
                CsvExporter csvExporter = new CsvExporter(csvPath, ropResult.first);
                csvExporter.exportData(ropResult.second);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
