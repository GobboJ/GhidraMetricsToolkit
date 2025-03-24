package impl.metrics;

import ghidra.framework.Application;
import ghidra.framework.OSFileNotFoundException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import impl.common.SimilarityInterface;
import impl.utils.LrzipWrapper;
import utils.ProjectUtils;

import java.io.File;


public class Ncd implements SimilarityInterface {

    private final String lrzipPath;

    public Ncd() {
        try {
            lrzipPath = Application.getOSFile("GhidraMetrics", "lrzip").getPath();
        } catch (OSFileNotFoundException e) {
            throw new RuntimeException(e);
        }
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

    public double computeBinarySimilarity(Program program1, Program program2) throws Exception {

        File f1 = ProjectUtils.exportProgram(program1);
        File f2 = ProjectUtils.exportProgram(program2);

        LrzipWrapper lrzipWrapper = new LrzipWrapper(lrzipPath);
        long size1 = lrzipWrapper.measure(f1);
        long size2 = lrzipWrapper.measure(f2);
        long sizeConcat = lrzipWrapper.measure(f1, f2);

        f1.delete();
        f2.delete();

        double value = 1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2);
        return Math.clamp(value, 0, 1);
    }

    @Override
    public double compute(Function function1, Function function2) {
        byte[] f1Bytes = getFunctionBytes(function1);
        byte[] f2Bytes = getFunctionBytes(function2);

        LrzipWrapper lrzipWrapper = new LrzipWrapper(lrzipPath);
        try {
            long size1 = lrzipWrapper.measure(f1Bytes);
            long size2 = lrzipWrapper.measure(f2Bytes);
            long sizeConcat = lrzipWrapper.measure(f1Bytes, f2Bytes);

            return Math.clamp(1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2), 0, 1);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
