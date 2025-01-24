package impl;

import generic.algorithms.ReducingListBasedLcs;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import impl.common.*;

import java.util.ArrayList;
import java.util.List;


public class Lcs implements MetricInterface {

    private final Program program1;
    private final Program program2;

    public Lcs(Program program1, Program program2) {
        this.program1 = program1;
        this.program2 = program2;
    }

    private static List<String> get_opcode_listing(Function function) {
        List<String> listing = new ArrayList<>();
        for (CodeUnit cb : function.getProgram().getListing().getCodeUnits(function.getBody(), true)) {
            listing.add(cb.toString());
        }
        return listing;
    }

    @Override
    public ResultInterface compute() {
        if (program1.getLanguage().getProcessor() != program2.getLanguage().getProcessor())
            return null;

        SimilarityResult matches = new SimilarityResult(program1, program2);

        for (Function f_1 : program1.getFunctionManager().getFunctions(true)) {
            if (f_1.isExternal() || f_1.isThunk())
                continue;
            double max = 0;
            Function max_2 = null;
            List<String> l_1 = get_opcode_listing(f_1);
            for (Function f_2 : program2.getFunctionManager().getFunctions(true)) {
                if (f_2.isExternal() || f_2.isThunk())
                    continue;
                List<String> l_2 = get_opcode_listing(f_2);
                ReducingListBasedLcs<String> rlcs = new ReducingListBasedLcs<>(l_1, l_2);
                rlcs.setSizeLimit(Integer.MAX_VALUE);
                double sim = rlcs.getLcs().size() * 2.0 / (l_1.size() + l_2.size());
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
