package impl;

import generic.stl.Pair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;


public class Entropy {

    public static ArrayList<Pair<String, Double>> entropyBySection(Program program) {

        ArrayList<Pair<String, Double>> entropyList = new ArrayList<>();
        Memory m = program.getMemory();
        for (MemoryBlock b : m.getBlocks()) {
            if (b.isExternalBlock() || !b.isInitialized()) {
                continue;
            }

            try {
                byte[] data = b.getData().readAllBytes();
                double res = computeEntropy(data, 2);
                entropyList.add(new Pair<>(b.getName(), res));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return entropyList;
    }

    public static double binaryEntropy(File file) throws IOException {
        byte[] content = Files.readAllBytes(file.toPath());
        return computeEntropy(content, 2);
    }

    private static double computeEntropy(byte[] data, float base) throws IOException {

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

}
