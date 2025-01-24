//Computes the entropy of the program
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import impl.Entropy;
import impl.common.ResultInterface;


public class EntropyScript extends GhidraScript {

    @Override
    protected void run() {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Entropy entropy = new Entropy(currentProgram);
        ResultInterface result = entropy.compute();
        printf(result.toString());
    }
}
