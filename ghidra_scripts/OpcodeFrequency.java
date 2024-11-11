//Computes the Opcode Frequency Similarity between two programs
//@author Ca' Foscari - Software Security
//@category Metrics

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.*;

public class OpcodeFrequency extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("no current program");
            return;
        }

        Program p2 = askProgram("Pick second program");
        Result r = opcode_frequency(currentProgram, p2);
        println(String.format("OpFreq[%s, %s] Overall similarity = %.2f", currentProgram.getName(), p2.getName(), r.overallSimilarity()));
        r.sortBySimilarity();
        print(r.toString());
    }

    Map<String, Double> get_histogram(Function function) {
        Map<String, Double> histogram = new HashMap<>();
        for (CodeUnit cb : function.getProgram().getListing().getCodeUnits(function.getBody(), true)) {
            String opcode = cb.toString().split(" ")[0];
            Double prev = histogram.putIfAbsent(opcode, 1.0);
            if (prev != null) {
                histogram.put(opcode, prev + 1);
            }
        }
        double count = histogram.values().stream().mapToDouble(a -> a).sum();
        histogram.replaceAll((key, value) -> value / count);
        return histogram;
    }

    private double computeDistance(Map<String, Double> histogram_1, Map<String, Double> histogram_2) {
        Set<String> opcodeSet = new HashSet<>(histogram_1.keySet());
        opcodeSet.addAll(histogram_2.keySet());

        double distance = 0.0;
        for (String opcode : opcodeSet) {
            distance += Math.pow(histogram_1.getOrDefault(opcode, 0.0) - histogram_2.getOrDefault(opcode, 0.0), 2);
        }

        return distance;
    }


    Result opcode_frequency(Program p1, Program p2) {

        Result result = new Result();
        for (Function f_1 : p1.getFunctionManager().getFunctions(true)) {
            if (f_1.isExternal() || f_1.isThunk())
                continue;
            Map<String, Double> histogram_1 = get_histogram(f_1);
            double min = Double.MAX_VALUE;
            Function f2_min = null;
            for (Function f_2 : p2.getFunctionManager().getFunctions(true)) {
                if (f_2.isExternal() || f_2.isThunk())
                    continue;
                Map<String, Double> histogram_2 = get_histogram(f_2);

                double distance = computeDistance(histogram_1, histogram_2);
                if (distance <= min) {
                    min = distance;
                    f2_min = f_2;
                }
            }
            if (min < Double.MAX_VALUE) {
                result.addMatch(f_1, f2_min, 1 - min);
            }
        }

        return result;
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
