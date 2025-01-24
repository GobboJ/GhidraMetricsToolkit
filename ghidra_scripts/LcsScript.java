//Computes the LCS Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import impl.Lcs;
import impl.common.SimilarityResult;
import utils.ProjectUtils;


public class LcsScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
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

        Lcs metric = new Lcs(currentProgram, p2);
        SimilarityResult res = (SimilarityResult) metric.compute();
        println(String.format("LCS[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), res.overallSimilarity()));
        res.sortBySimilarity();
        print(res.toString());
    }

}
