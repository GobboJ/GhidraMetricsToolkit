//Computes the entropy of the program
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import impl.Entropy;
import utils.ProjectUtils;

import java.io.File;


public class EntropyScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }
        File programFile = ProjectUtils.exportProgram(currentProgram);
        double res = Entropy.binaryEntropy(programFile);
        printf("Binary Entropy: %.2f\n", res);

        println("Entropy by section:");
        for (Pair<String, Double> section : Entropy.entropyBySection(currentProgram)) {
            printf("\t%s: %.2f\n", section.first, section.second);
        }

        programFile.delete();
    }

}
