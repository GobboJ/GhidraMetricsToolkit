//Computes the NCD Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.Ncd;
import impl.common.SimilarityResult;
import impl.utils.CsvExporter;
import picocli.CommandLine;
import utils.ProjectUtils;

import java.io.IOException;
import java.util.List;


public class NcdScript extends GhidraScript {

    static class ScriptArgs {
        @CommandLine.Parameters(index = "0", description = "The program to compare to")
        String programName;

        @CommandLine.Option(names = "--csv-export", description = "CSV file path to export result")
        String csvPath;

        @CommandLine.Option(names = "--binary-only", description = "Only compute overall binary similarity")
        boolean binaryOnly;
    }

    @Override
    protected void run() throws Exception {

        String os = System.getProperty("os.name").toLowerCase();

        if (!os.contains("linux")) {
            println("NCD is only available on linux");
            return;
        }

        Program p2;
        String csvPath = null;
        boolean binaryOnly = false;

        if (isRunningHeadless()) {
            ScriptArgs args = new ScriptArgs();
            CommandLine cmd = new CommandLine(args);
            cmd.parseArgs(getScriptArgs());

            p2 = ProjectUtils.getProgramByName(state.getProject(), args.programName);
            csvPath = args.csvPath;
            binaryOnly = args.binaryOnly;

        } else {
            p2 = askProgram("Pick second program");
        }

        if (p2 == null) {
            printerr("second program not found");
            return;
        }

        Ncd metric = new Ncd(currentProgram, p2, binaryOnly);

        SimilarityResult result = (SimilarityResult) metric.compute();
        if (result == null) {
            printerr("The programs have different processors. Aborting");
            return;
        }

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
