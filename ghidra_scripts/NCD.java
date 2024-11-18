//Computes the NCD Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

import java.io.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class NCD extends GhidraScript {

    private static final String LRZIP_PATH = "os/linux_x86_64/lrzip";

    @Override
    protected void run() throws Exception {

        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("linux")) {

            File programFile = promptFileChooser(currentProgram);
            Program p2 = askProgram("Pick second program");
            File p2File = promptFileChooser(p2);

            if (programFile.exists() && p2File.exists()) {
                double res = ncdSimilarity(programFile, p2File);
                ncdFunctionSimilarity(currentProgram, p2);
                println(String.format("NCD[%s, %s] Similarity: %f", currentProgram.getName(), p2.getName(), res));

                Result fRes = ncdFunctionSimilarity(currentProgram, p2);
                fRes.sortBySimilarity();
                print(fRes.toString());
            }

        }
    }

    private File promptFileChooser(Program program) throws CancelledException {
        File f = new File(program.getExecutablePath());
        if (!f.exists()) {
            if (!isRunningHeadless()) {
                println("Couldn't find the program file, please choose one:");
                f = askFile("Select program file", "Select File");
            } else {
                printerr("Couldn't find the program file, aborting...");
            }
        }
        return f;
    }

    public double ncdSimilarity(File f1, File f2) throws Exception {

        long size1 = LrzipWrapper.measure(f1);
        long size2 = LrzipWrapper.measure(f2);
        long sizeConcat = LrzipWrapper.measure(f1, f2);

        return 1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2);
    }

    private byte[] getFunctionBytes(Function function) {
        Memory memory = function.getProgram().getMemory();
        byte[] functionBytes = new byte[(int) function.getBody().getNumAddresses()];
        try {
            memory.getBytes(function.getEntryPoint(), functionBytes);
        } catch (MemoryAccessException e) {
            throw new RuntimeException(e);
        }
        return functionBytes;
    }

    public Result ncdFunctionSimilarity(Program p1, Program p2) throws Exception {
        Result matches = new Result();
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

                long size1 = LrzipWrapper.measure(f1Bytes);
                long size2 = LrzipWrapper.measure(f2Bytes);
                long sizeConcat = LrzipWrapper.measure(f1Bytes, f2Bytes);

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

    public static class Result {
        private static class Match {
            Function f1;
            Function f2;
            double similarity;

            public Match(Function f1, Function f2, double similarity) {
                this.f1 = f1;
                this.f2 = f2;
                this.similarity = similarity;
            }
        }

        private final List<Match> matches;

        private Result() {
            matches = new ArrayList<>();
        }

        private void addMatch(Function f1, Function f2, double similarity) {
            matches.add(new Match(f1, f2, similarity));
        }

        public void sortBySimilarity() {
            matches.sort(Comparator.comparingDouble(m -> -m.similarity));
        }

        public void sortByName() {
            matches.sort(Comparator.comparing(m -> m.f1.getName()));
        }

        public double overallSimilarity() {
            return matches.stream().mapToDouble(m -> m.similarity).sum() / matches.size();
        }

        @Override
        public String toString() {
            StringBuilder output = new StringBuilder();
            output.append("Function matching:\n");
            for (Match m : matches) {
                output.append(String.format("%.2f | %-20s | %-20s\n", m.similarity, m.f1.getName(), m.f2.getName()));
            }
            return output.toString();
        }
    }

    private static class LrzipWrapper {

        private static File concatenate(File f1, File f2) {
            File fConcat = new File(f1.getParent(), String.format("concat_%s_%s.bin", f1.getName(), f2.getName()));
            try (FileOutputStream outputStream = new FileOutputStream(fConcat);
                 FileInputStream inputStream1 = new FileInputStream(f1);
                 FileInputStream inputStream2 = new FileInputStream(f2)) {

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = inputStream1.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                while ((bytesRead = inputStream2.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }

                return fConcat;

            } catch (IOException e) {
                return null;
            }
        }

        private static File compress(File f) throws Exception {
            ProcessBuilder builder = new ProcessBuilder(LRZIP_PATH, "--best", "-f", f.getAbsolutePath());
            Process process = builder.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new Exception("Compression failed");
            }
            return new File(f.getAbsolutePath() + ".lrz");
        }

        public static long measure(File f) throws Exception {
            File compressed = compress(f);
            long compressedLen = compressed.length();
            boolean delete = compressed.delete();
            return compressedLen;
        }

        public static long measure(File f1, File f2) throws Exception {
            File concat = concatenate(f1, f2);
            long compressedLen = measure(concat);
            boolean delete = concat.delete();
            return compressedLen;
        }

        public static long measure(byte[] bytes) throws Exception {
            File tmp = new File("compress.tmp");
            try (FileOutputStream stream = new FileOutputStream(tmp)) {
                stream.write(bytes);
            }
            long res = measure(tmp);
            tmp.delete();
            return res;
        }

        public static long measure(byte[] bytes1, byte[] bytes2) throws Exception {
            byte[] concat = new byte[bytes1.length + bytes2.length];
            System.arraycopy(bytes1, 0, concat, 0, bytes1.length);
            System.arraycopy(bytes2, 0, concat, bytes1.length, bytes2.length);
            return measure(concat);
        }
    }
}
