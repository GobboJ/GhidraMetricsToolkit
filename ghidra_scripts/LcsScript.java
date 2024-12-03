//Computes the LCS Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import impl.Lcs;
import impl.common.SimilarityResult;


public class LcsScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program p2 = askProgram("Pick second program");
        Lcs metric = new Lcs();
        SimilarityResult res = metric.computeSimilarity(currentProgram, p2);
        println(String.format("LCS[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), res.overallSimilarity()));
        res.sortBySimilarity();
        print(res.toString());
    }

}
