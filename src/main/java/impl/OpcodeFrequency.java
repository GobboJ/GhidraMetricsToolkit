package impl;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import impl.common.SimilarityInterface;
import impl.common.SimilarityResult;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class OpcodeFrequency implements SimilarityInterface {

    private static Map<String, Double> get_histogram(Function function) {
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

    private static double computeDistance(Map<String, Double> histogram_1, Map<String, Double> histogram_2) {
        Set<String> opcodeSet = new HashSet<>(histogram_1.keySet());
        opcodeSet.addAll(histogram_2.keySet());

        double distance = 0.0;
        for (String opcode : opcodeSet) {
            distance += Math.pow(histogram_1.getOrDefault(opcode, 0.0) - histogram_2.getOrDefault(opcode, 0.0), 2);
        }

        return distance;
    }

    @Override
    public SimilarityResult computeSimilarity(Program p1, Program p2) {

        if (p1.getLanguage().getProcessor() != p2.getLanguage().getProcessor())
            return null;

        SimilarityResult result = new SimilarityResult(p1, p2);
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

}
