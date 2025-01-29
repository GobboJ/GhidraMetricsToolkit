//Computes the Opcode Frequency Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.OpcodeFrequency;
import impl.common.SimilarityResult;
import impl.utils.CsvExporter;
import picocli.CommandLine;
import utils.ProjectUtils;

import java.io.IOException;
import java.util.List;


public class OpcodeFrequencyScript extends GhidraScript {

    static class ScriptArgs {
        @CommandLine.Parameters(index = "0", description = "The program to compare to")
        String programName;

        @CommandLine.Option(names = "--csv-export", description = "CSV file path to export result")
        String csvPath;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program program2;
        String csvPath = null;

        if (isRunningHeadless()) {
            ScriptArgs args = new ScriptArgs();
            CommandLine cmd = new CommandLine(args);
            cmd.parseArgs(getScriptArgs());
            program2 = ProjectUtils.getProgramByName(state.getProject(), args.programName);
            csvPath = args.csvPath;
        } else {
            program2 = askProgram("Pick second program");
        }

        OpcodeFrequency metric = new OpcodeFrequency(currentProgram, program2);
        SimilarityResult result = (SimilarityResult) metric.compute();

        if (result == null) {
            printerr("The programs have different processors. Aborting");
            return;
        }
        result.calculateOverallSimilarity();
        result.sortBySimilarity();

        print(result.toString());

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
