package utils;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

public class ProjectUtils {

    public static void findProgramsRecursively(DomainFolder folder, List<DomainFile> programFiles) {
        // Add programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if (Program.class.isAssignableFrom(file.getDomainObjectClass())) {
                programFiles.add(file);
            }
        }

        // Recurse into subfolders
        for (DomainFolder subFolder : folder.getFolders()) {
            findProgramsRecursively(subFolder, programFiles);
        }
    }

    public static Program getProgramFromDomainFile(DomainFile domainFile) {

        Program program = null;
        int openMode = DomainFile.DEFAULT_VERSION;
        TaskMonitor monitor = TaskMonitor.DUMMY;

        try {
            // Open the domain file as a Program
            DomainObject domainObject = domainFile.getDomainObject(openMode, false, false, monitor);
            if (domainObject instanceof Program) {
                program = (Program) domainObject;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CancelledException | VersionException e) {
            throw new RuntimeException(e);
        }

        return program;
    }
}
