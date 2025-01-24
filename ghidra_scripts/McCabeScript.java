//Computes the McCabe cyclomatic complexity of the whole program
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import impl.McCabe;


public class McCabeScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        McCabe complexity = new McCabe(currentProgram);
        println("Complexity: " + complexity.compute());
    }
}
