package impl;

import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import impl.common.SimilarityInterface;
import impl.common.SimilarityResult;
import impl.utils.LrzipWrapper;
import java.io.File;


public class Ncd implements SimilarityInterface {

    private final String lrzipPath;

    public Ncd() throws OSFileNotFoundException {
        lrzipPath = Application.getOSFile("GhidraMetrics", "lrzip").getPath();
    }

    public double ncdSimilarity(File f1, File f2) throws Exception {

        LrzipWrapper lrzipWrapper = new LrzipWrapper(lrzipPath);
        long size1 = lrzipWrapper.measure(f1);
        long size2 = lrzipWrapper.measure(f2);
        long sizeConcat = lrzipWrapper.measure(f1, f2);

        double value = 1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2);
        return Math.clamp(value, 0, 1);
    }

    private static byte[] getFunctionBytes(Function function) {
        Memory memory = function.getProgram().getMemory();
        byte[] functionBytes = new byte[(int) function.getBody().getNumAddresses()];
        try {
            memory.getBytes(function.getEntryPoint(), functionBytes);
        } catch (MemoryAccessException e) {
            throw new RuntimeException(e);
        }
        return functionBytes;
    }

    @Override
    public SimilarityResult computeSimilarity(Program p1, Program p2) throws Exception {
        SimilarityResult matches = new SimilarityResult(p1, p2);
        for (Function f_1 : p1.getFunctionManager().getFunctions(true)) {
            if (f_1.isExternal() || f_1.isThunk())
                continue;
            byte[] f1Bytes = getFunctionBytes(f_1);
            double max = 0;
            Function max_2 = null;
            for (Function f_2 : p2.getFunctionManager().getFunctions(true)) {
                if (f_2.isExternal() || f_2.isThunk())
                    continue;
                byte[] f2Bytes = getFunctionBytes(f_2);

                LrzipWrapper lrzipWrapper = new LrzipWrapper(lrzipPath);
                long size1 = lrzipWrapper.measure(f1Bytes);
                long size2 = lrzipWrapper.measure(f2Bytes);
                long sizeConcat = lrzipWrapper.measure(f1Bytes, f2Bytes);

                double sim = 1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2);

                if (sim >= max) {
                    max = sim;
                    max_2 = f_2;
                }
            }
            if (max > 0) {
                matches.addMatch(f_1, max_2, max);
            }
        }
        return matches;
    }

}
