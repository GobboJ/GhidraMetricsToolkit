//Computes the Halstead metrics of a function and the entire program
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import impl.Halstead;


public class HalsteadScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }


        Function currentFunction = currentProgram.getFunctionManager().getFunctionAt(currentAddress);

        Halstead halstead = new Halstead(currentProgram, currentFunction);
        Halstead.Result result = (Halstead.Result) halstead.compute();
        printf(result.toString());
    }

}
