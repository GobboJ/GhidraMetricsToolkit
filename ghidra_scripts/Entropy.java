//Computes the entropy of the program
//@author Ca' Foscari - Software Security
//@category Metrics

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;


public class Entropy extends GhidraScript {

    private ArrayList<Pair<String, Double>> sectionsEntropy() {

        ArrayList<Pair<String, Double>> entropies = new ArrayList<>();
        Memory m = currentProgram.getMemory();
        for (MemoryBlock b : m.getBlocks()) {
            if (b.isExternalBlock() || !b.isInitialized()) {
                continue;
            }

            try {
                byte[] data = b.getData().readAllBytes();
                double res = computeEntropy(data, 2);
                entropies.add(new Pair<>(b.getName(), res));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return entropies;
    }

    private double binaryEntropy(File file) throws IOException {
        byte[] content = Files.readAllBytes(file.toPath());
        return computeEntropy(content, 2);
    }

    private double computeEntropy(byte[] data, float base) throws IOException {

        int[] freq = new int[0x100];
        for (byte b : data) {
            freq[b & 0xff] += 1;
        }

        double entropy = 0.0;
        for (int j : freq) {
            double p = (double) j / data.length;
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

        File programFile = new File(currentProgram.getExecutablePath());
        if (!programFile.exists()) {
            if (!isRunningHeadless()) {
                println("Couldn't find the program file, please choose one:");
                programFile = askFile("Select program file", "Select File");
            } else {
                printerr("Couldn't find the program file, aborting...");
            }
        }
        double res = binaryEntropy(programFile);
        printf("Binary Entropy: %.2f\n", res);

        println("Entropy by section:");
        for (Pair<String, Double> section : sectionsEntropy()) {
            printf("\t%s: %.2f\n", section.first, section.second);
        }
    }
}
