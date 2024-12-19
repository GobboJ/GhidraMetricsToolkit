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

    public static void getProgramList(DomainFolder folder, List<DomainFile> programFiles) {
        for (DomainFile file : folder.getFiles()) {
            if (Program.class.isAssignableFrom(file.getDomainObjectClass())) {
                programFiles.add(file);
            }
        }
        for (DomainFolder subFolder : folder.getFolders()) {
            getProgramList(subFolder, programFiles);
        }
    }

    public static Program getProgramFromDomainFile(DomainFile domainFile) {

        Program program = null;

        try {
            DomainObject domainObject = domainFile.getDomainObject(DomainFile.DEFAULT_VERSION, false, false, TaskMonitor.DUMMY);
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
