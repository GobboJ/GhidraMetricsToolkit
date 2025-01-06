//Computes the ROP Survival metrics between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.RopSurvival;
import utils.ProjectUtils;

public class RopSurvivalScript extends GhidraScript {

    private static final String DEPTH = "10";

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

        double bagOfGadgetsSimilarity = RopSurvival.bagOfGadgetsSimilarity(currentProgram, p2, DEPTH);
        println(String.format("Bag of Gadgets [%s, %s]: %f", currentProgram.getName(), p2.getName(), bagOfGadgetsSimilarity));

        double survivorSimilarity = RopSurvival.survivorSimilarity(currentProgram, p2, DEPTH);
        println(String.format("Survivor [%s, %s]: %f", currentProgram.getName(), p2.getName(), survivorSimilarity));
    }

}
