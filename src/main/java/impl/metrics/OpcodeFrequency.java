package impl.metrics;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import impl.common.SimilarityInterface;

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

    private static double computeSimilarity(Map<String, Double> histogram_1, Map<String, Double> histogram_2) {
        Set<String> opcodeSet = new HashSet<>(histogram_1.keySet());
        opcodeSet.addAll(histogram_2.keySet());

        double distance = 0.0;
        for (String opcode : opcodeSet) {
            distance += Math.pow(histogram_1.getOrDefault(opcode, 0.0) - histogram_2.getOrDefault(opcode, 0.0), 2);
        }

        return 1 - distance;
    }

    @Override
    public double compute(Function function1, Function function2) {
        Map<String, Double> histogram1 = get_histogram(function1);
        Map<String, Double> histogram2 = get_histogram(function2);
        return computeSimilarity(histogram1, histogram2);
    }
}
