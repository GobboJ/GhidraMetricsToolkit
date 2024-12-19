package impl;

import ghidra.program.model.listing.Program;
import impl.utils.RopGadgetWrapper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class RopSurvival {

    public static double bagOfGadgetsSimilarity(Program program1, Program program2, String depth) throws Exception {
        HashMap<Long, String> rops1 = RopGadgetWrapper.getRops(program1, depth);
        HashMap<Long, String> rops2 = RopGadgetWrapper.getRops(program2, depth);

        Set<String> intersection = new HashSet<>(rops1.values());
        int size = intersection.size();
        intersection.retainAll(rops2.values());

        return (double) intersection.size() / size;
    }

    public static double survivorSimilarity(Program program1, Program program2, String depth) throws Exception {
        HashMap<Long, String> rops1 = RopGadgetWrapper.getRops(program1, depth);
        HashMap<Long, String> rops2 = RopGadgetWrapper.getRops(program2, depth);

        int len = rops1.size();
        rops1.entrySet().retainAll(rops2.entrySet());

        return (double) rops1.size() / len;
    }

}
