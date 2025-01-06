//Computes the NCD Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.io.*;
import impl.Ncd;
import impl.common.SimilarityResult;
import utils.ProjectUtils;


public class NcdScript extends GhidraScript {

    @Override
    protected void run() throws Exception {

        String os = System.getProperty("os.name").toLowerCase();

        if (!os.contains("linux")) {
            println("NCD is only available on linux");
            return;
        }

        Program p2;
        if (isRunningHeadless()) {
            String[] args = getScriptArgs();
            if (args.length != 1) {
                printerr("One parameter expected");
                return;
            }
            String programName = args[0];
            p2 = ProjectUtils.getProgramByName(state.getProject(), programName);
        } else {
            p2 = askProgram("Pick second program");
        }

        if (p2 == null) {
            printerr("second program not found");
            return;
        }

        File programFile = ProjectUtils.exportProgram(currentProgram);
        File p2File = ProjectUtils.exportProgram(p2);
        if (programFile.exists() && p2File.exists()) {
            Ncd metric = new Ncd();
            double res = metric.ncdSimilarity(programFile, p2File);
            println(String.format("NCD[%s, %s] Similarity: %f", currentProgram.getName(), p2.getName(), res));

            SimilarityResult fRes = metric.computeSimilarity(currentProgram, p2);
            fRes.sortBySimilarity();
            print(fRes.toString());
        }

        programFile.delete();
        p2File.delete();
    }

}
