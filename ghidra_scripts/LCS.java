//Computes the LCS Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import generic.algorithms.ReducingListBasedLcs;
import ghidra.program.model.listing.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class LCS extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program p2 = askProgram("Pick second program");
        Result res = lcs_similarity(currentProgram, p2);
        println(String.format("LCS[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), res.overallSimilarity()));
        res.sortBySimilarity();
        print(res.toString());
    }

    private List<String> get_opcode_listing(Function function) {
        List<String> listing = new ArrayList<>();
        for (CodeUnit cb : function.getProgram().getListing().getCodeUnits(function.getBody(), true)) {
            listing.add(cb.toString());
        }
        return listing;
    }

    public Result lcs_similarity(Program p1, Program p2) {

        Result matches = new Result();

        for (Function f_1 : p1.getFunctionManager().getFunctions(true)) {
            if (f_1.isExternal() || f_1.isThunk())
                continue;
            double max = 0;
            Function max_2 = null;
            List<String> l_1 = get_opcode_listing(f_1);
            for (Function f_2 : p2.getFunctionManager().getFunctions(true)) {
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

}
