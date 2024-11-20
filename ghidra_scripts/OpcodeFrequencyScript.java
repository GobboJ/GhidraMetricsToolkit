//Computes the Opcode Frequency Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.OpcodeFrequency;
import impl.common.SimilarityResult;


public class OpcodeFrequencyScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program p2 = askProgram("Pick second program");
        SimilarityResult r = OpcodeFrequency.opcode_frequency(currentProgram, p2);
        println(String.format("OpFreq[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), r.overallSimilarity()));
        r.sortBySimilarity();
        print(r.toString());
    }

}
