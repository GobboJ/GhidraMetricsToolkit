package impl;

import generic.stl.Pair;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import impl.common.MetricInterface;
import impl.common.ResultInterface;
import utils.ProjectUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;


public class Entropy implements MetricInterface {

    private final Program program;
    private final int base;

    public Entropy(Program program, int base) {
        this.program = program;
        this.base = base;
    }

    public Entropy(Program program) {
        this.program = program;
        this.base = 2;
    }

    public static class Result implements ResultInterface {
        public final double binaryEntropy;
        public final ArrayList<Pair<String, Double>> sectionEntropy;

        public Result(double binaryEntropy, ArrayList<Pair<String, Double>> sectionEntropy) {
            this.binaryEntropy = binaryEntropy;
            this.sectionEntropy = sectionEntropy;
        }

        @Override
        public void export() {

        }

        @Override
        public String toString() {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(String.format("Binary Entropy: %.2f\n", binaryEntropy));
            stringBuilder.append("Entropy by section:\n");
            for (Pair<String, Double> section : sectionEntropy) {
                stringBuilder.append(String.format("\t%s: %.2f\n", section.first, section.second));
            }
            return stringBuilder.toString();
        }
    }

    @Override
    public ResultInterface compute() {
        return new Result(binaryEntropy(), entropyBySection());
    }

    private ArrayList<Pair<String, Double>> entropyBySection() {

        ArrayList<Pair<String, Double>> entropyList = new ArrayList<>();
        Memory m = program.getMemory();
        for (MemoryBlock b : m.getBlocks()) {
            if (b.isExternalBlock() || !b.isInitialized()) {
                continue;
            }

            try {
                byte[] data = b.getData().readAllBytes();
                double res = computeEntropy(data);
                entropyList.add(new Pair<>(b.getName(), res));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return entropyList;
    }

    private double binaryEntropy() {
        try {
            File f = ProjectUtils.exportProgram(this.program);
            byte[] content = Files.readAllBytes(f.toPath());
            f.delete();
            return computeEntropy(content);
        } catch (CancelledException | IOException | VersionException | ExporterException e) {
            throw new RuntimeException(e);
        }
    }

    private double computeEntropy(byte[] data) throws IOException {

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
