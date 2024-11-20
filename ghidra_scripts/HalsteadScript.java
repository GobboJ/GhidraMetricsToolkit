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
        if (currentFunction != null) {
            println("Halstead metrics for function: " + currentFunction.getName());
            print(Halstead.halsteadByFunction(currentFunction).toString());
        }

        println("Halstead metric for whole program");
        print(Halstead.halsteadByProgram(currentProgram).toString());
    }

}
