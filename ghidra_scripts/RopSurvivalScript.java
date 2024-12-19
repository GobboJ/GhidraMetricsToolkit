//Computes the ROP Survival metrics between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.RopSurvival;

public class RopSurvivalScript extends GhidraScript {

    private static final String DEPTH = "10";

    @Override
    protected void run() throws Exception {

        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program p2 = askProgram("Select second program");

        double bagOfGadgetsSimilarity = RopSurvival.bagOfGadgetsSimilarity(currentProgram, p2, DEPTH);
        println(String.format("Bag of Gadgets [%s, %s]: %f", currentProgram.getName(), p2.getName(), bagOfGadgetsSimilarity));

        double survivorSimilarity = RopSurvival.survivorSimilarity(currentProgram, p2, DEPTH);
        println(String.format("Survivor [%s, %s]: %f", currentProgram.getName(), p2.getName(), survivorSimilarity));
    }

}
