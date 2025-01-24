package impl;

import generic.stl.Pair;
import ghidra.program.model.listing.*;
import impl.common.MetricInterface;
import impl.common.ResultInterface;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


public class Halstead implements MetricInterface {

    private final Program program;
    private final Function function;

    public Halstead(Program program, Function function) {
        this.program = program;
        this.function = function;
    }

    public Halstead(Program program) {
        this.program = program;
        this.function = null;
    }

    @Override
    public ResultInterface compute() {
        int[] ops = halsteadByProgram();
        int[] fOps = null;
        if (this.function != null) {
            fOps = halsteadByFunction(this.function);
        }
        return new Result(ops, fOps);
    }

    public static class Result implements ResultInterface {

        public List<Pair<String, Double>> halstead;
        public List<Pair<String, Double>> functionHalstead;

        private List<Pair<String, Double>> generateMetrics(int[] ops) {
            List<Pair<String, Double>> metrics = new ArrayList<>();
            int n_1 = ops[0];
            metrics.add(new Pair<>("n_1", (double) n_1));
            int n_2 = ops[1];
            metrics.add(new Pair<>("n_2", (double) n_2));
            int N_1 = ops[2];
            metrics.add(new Pair<>("N_1", (double) N_1));
            int N_2 = ops[3];
            metrics.add(new Pair<>("N_2", (double) N_2));

            int programVocab = n_1 + n_2;
            metrics.add(new Pair<>("Program Vocabulary (n)", (double) programVocab));
            int programLength = N_1 + N_2;
            metrics.add(new Pair<>("Program Length (N)", (double) programLength));

            double estimatedLength = n_1 * Math.log(n_1) + n_2 * Math.log(n_2);
            metrics.add(new Pair<>("Estimated Length (~N)", estimatedLength));
            double volume = programLength * Math.log(programVocab);
            metrics.add(new Pair<>("Volume (V)", volume));
            double difficulty = (double) n_1 / 2 * N_2 / 2;
            metrics.add(new Pair<>("Difficulty (D)", difficulty));
            double effort = volume * difficulty;
            metrics.add(new Pair<>("Effort (E)", effort));
            double timeToProgram = effort / 18;
            metrics.add(new Pair<>("Time to Program (T)", timeToProgram));
            double deliveredBugs = volume / 3000;
            metrics.add(new Pair<>("Delivered Bugs (B)", deliveredBugs));

            return metrics;
        }

        public Result(int[] ops, int[] fOps) {
            if (ops != null) {
                halstead = generateMetrics(ops);
            }
            if (fOps != null) {
                functionHalstead = generateMetrics(fOps);
            }
        }

        @Override
        public void export() {

        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("Program Halstead Metrics:\n");
            for (var e : halstead) {
                builder.append(String.format(e.first + ": %15.2f\n", e.second));
            }
            if (functionHalstead != null) {
                builder.append("Function Halstead Metrics:\n");
                for (var e : functionHalstead) {
                    builder.append(String.format(e.first + ": %15.2f\n", e.second));
                }
            }
            return builder.toString();
        }
    }

    private int[] halsteadByProgram() {
        int[] ops = new int[4];
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        for (Function f : functions) {
            int[] fOps = halsteadByFunction(f);
            if (fOps != null) {
                for (int i = 0; i < 4; i++)
                    ops[i] += fOps[i];
            }
        }
        return ops;
    }

    private int[] halsteadByFunction(Function function) {

        if (function.isThunk() || function.isExternal())
            return null;

        ArrayList<String> operands = new ArrayList<>();
        ArrayList<String> operators = new ArrayList<>();

        Listing l = function.getProgram().getListing();
        InstructionIterator it = l.getInstructions(function.getBody(), true);

        while (it.hasNext()) {
            Instruction instr = it.next();
            String operator = instr.getMnemonicString();
            operators.add(operator);
            int numOp = instr.getNumOperands();
            for (int j = 0; j < numOp; j++) {
                Object[] ops = instr.getOpObjects(j);
                for (Object o : ops) {
                    operands.add(o.toString());
                }
            }
        }

        return new int[]{ new HashSet<>(operators).size(), new HashSet<>(operands).size(), operators.size(), operands.size() };
    }

}
