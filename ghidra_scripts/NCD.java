//Computes the NCD Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

import java.io.*;

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
                double res = ncd_similarity(programFile, p2File);
                println(String.format("NCD[%s, %s] Similarity: %f", currentProgram.getName(), p2.getName(), res));
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

    public double ncd_similarity(File f1, File f2) throws Exception {

        long size1 = LrzipWrapper.measure(f1);
        long size2 = LrzipWrapper.measure(f2);
        long sizeConcat = LrzipWrapper.measure(f1, f2);

        return 1 - (double) (sizeConcat - Math.min(size1, size2)) / Math.max(size1, size2);
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
            compressed.delete();
            return compressedLen;
        }

        public static long measure(File f1, File f2) throws Exception {
            File concat = concatenate(f1, f2);
            long compressedLen = measure(concat);
            concat.delete();
            return compressedLen;
        }
    }
}
