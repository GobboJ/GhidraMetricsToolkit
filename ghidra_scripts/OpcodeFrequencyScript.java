//Computes the Opcode Frequency Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.OpcodeFrequency;
import impl.common.SimilarityResult;
import utils.ProjectUtils;


public class OpcodeFrequencyScript extends GhidraScript {

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

        OpcodeFrequency metric = new OpcodeFrequency();
        SimilarityResult r = metric.computeSimilarity(currentProgram, p2);

        if (r == null) {
            printerr("The programs have different processors. Aborting");
            return;
        }

        println(String.format("OpFreq[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), r.overallSimilarity()));
        r.sortBySimilarity();
        print(r.toString());
    }

}
