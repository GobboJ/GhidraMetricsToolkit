//Computes the entropy of the program
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;



public class Entropy extends GhidraScript {

    private double computeEntropy(File program, float base) throws IOException {
        byte[] content = Files.readAllBytes(program.toPath());

        int[] freq = new int[0x100];
        for (byte b : content) {
            freq[b & 0xff] += 1;
        }

        double entropy = 0.0;
        for (int j : freq) {
            double p = (double) j / content.length;
            if (j > 0) {
                entropy -= p * Math.log(p) / Math.log(base);
            }
        }
        return entropy;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        File f = new File(currentProgram.getExecutablePath());
        if (f.exists()) {
            double result = computeEntropy(f, 2);
            println("Entropy: " + result);

        } else {
            if (!isRunningHeadless()) {
                println("Couldn't find the program file, please choose one:");
                File f1 = askFile("Select program file", "Select File");
                double result = computeEntropy(f1, 2);
                println("Entropy: " + result);
            } else {
                println("Couldn't find the program file, aborting...");
            }
        }
    }
}
