package impl;

import generic.algorithms.ReducingListBasedLcs;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import impl.common.SimilarityInterface;

import java.util.ArrayList;
import java.util.List;


public class Lcs implements SimilarityInterface {

    private static List<String> get_opcode_listing(Function function) {
        List<String> listing = new ArrayList<>();
        for (CodeUnit cb : function.getProgram().getListing().getCodeUnits(function.getBody(), true)) {
            listing.add(cb.toString());
        }
        return listing;
    }

    @Override
    public double compute(Function function1, Function function2) {
        List<String> l1 = get_opcode_listing(function1);
        List<String> l2 = get_opcode_listing(function2);
        ReducingListBasedLcs<String> rlcs = new ReducingListBasedLcs<>(l1, l2);
        rlcs.setSizeLimit(Integer.MAX_VALUE);
        return rlcs.getLcs().size() * 2.0 / (l1.size() + l2.size());
    }
}
