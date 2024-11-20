//Computes the entropy of the program
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import impl.Entropy;
import java.io.File;


public class EntropyScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        File programFile = new File(currentProgram.getExecutablePath());
        if (!programFile.exists()) {
            if (!isRunningHeadless()) {
                println("Couldn't find the program file, please choose one:");
                programFile = askFile("Select program file", "Select File");
            } else {
                printerr("Couldn't find the program file, aborting...");
            }
        }
        double res = Entropy.binaryEntropy(programFile);
        printf("Binary Entropy: %.2f\n", res);

        println("Entropy by section:");
        for (Pair<String, Double> section : Entropy.entropyBySection(currentProgram)) {
            printf("\t%s: %.2f\n", section.first, section.second);
        }
    }

}
