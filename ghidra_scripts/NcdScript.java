//Computes the NCD Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.*;
import impl.Ncd;
import impl.common.SimilarityResult;


public class NcdScript extends GhidraScript {

    @Override
    protected void run() throws Exception {

        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("linux")) {

            File programFile = promptFileChooser(currentProgram);
            Program p2 = askProgram("Pick second program");
            File p2File = promptFileChooser(p2);

            if (programFile.exists() && p2File.exists()) {
                Ncd metric = new Ncd();
                double res = metric.ncdSimilarity(programFile, p2File);
                println(String.format("NCD[%s, %s] Similarity: %f", currentProgram.getName(), p2.getName(), res));

                SimilarityResult fRes = metric.computeSimilarity(currentProgram, p2);
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

}
