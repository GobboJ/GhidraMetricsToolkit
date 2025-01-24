package impl;

import ghidra.program.model.listing.Program;
import impl.common.MetricInterface;
import impl.common.ResultInterface;
import impl.utils.RopGadgetWrapper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class RopSurvival implements MetricInterface {

    private final Program program1;
    private final Program program2;
    private int depth;

    public RopSurvival(Program program1, Program program2, int depth) {
        this.program1 = program1;
        this.program2 = program2;
        this.depth = depth;
    }

    public RopSurvival(Program program1, Program program2) {
        this(program1, program2, 10);
    }

    public static class Result implements ResultInterface {

        public final double bagOfGadgets;
        public final double survivor;

        public Result(double bagOfGadgets, double survivor) {
            this.bagOfGadgets = bagOfGadgets;
            this.survivor = survivor;
        }

        @Override
        public void export() {

        }

        @Override
        public String toString() {
            return String.format("Bag of Gadgets: %f\nSurvivor: %f", bagOfGadgets, survivor);
        }
    }

    private double bagOfGadgetsSimilarity() {
        try {
            HashMap<Long, String> gadgets1 = RopGadgetWrapper.getRops(program1, depth);
            HashMap<Long, String> gadgets2 = RopGadgetWrapper.getRops(program2, depth);

            Set<String> intersection = new HashSet<>(gadgets1.values());
            int size = intersection.size();
            intersection.retainAll(gadgets2.values());

            return (double) intersection.size() / size;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private double survivorSimilarity() {
        try {
            HashMap<Long, String> gadgets1 = RopGadgetWrapper.getRops(program1, depth);
            HashMap<Long, String> gadgets2 = RopGadgetWrapper.getRops(program2, depth);

            int len = gadgets1.size();
            gadgets1.entrySet().retainAll(gadgets2.entrySet());

            return (double) gadgets1.size() / len;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ResultInterface compute() {
        if (program1.getLanguage().getProcessor() != program2.getLanguage().getProcessor())
            return null;
        return new Result(bagOfGadgetsSimilarity(), survivorSimilarity());
    }
}
