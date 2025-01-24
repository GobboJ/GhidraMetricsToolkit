//Computes the ROP Survival metrics between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import impl.RopSurvival;
import utils.ProjectUtils;

public class RopSurvivalScript extends GhidraScript {

    private static int DEPTH = 10;

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

        RopSurvival ropSurvival = new RopSurvival(currentProgram, p2, DEPTH);
        RopSurvival.Result result = (RopSurvival.Result) ropSurvival.compute();

        if (result == null) {
            printerr("The programs have different processors. Aborting");
            return;
        }

        printf(result.toString());
    }

}
