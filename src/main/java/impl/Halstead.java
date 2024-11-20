package impl;

import ghidra.program.model.listing.*;
import java.util.ArrayList;
import java.util.HashSet;


public class Halstead {

    public static Result halsteadByProgram(Program program) {
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        Result res = new Result(0, 0, 0, 0);
        for (Function f : functions) {
            res.add(halsteadByFunction(f));
        }
        return res;
    }

    public static Result halsteadByFunction(Function function) {

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

        return new Result(new HashSet<>(operators).size(), new HashSet<>(operands).size(), operators.size(), operands.size());
    }

    public static class Result {
        int n_1;
        int n_2;
        int N_1;
        int N_2;

        public Result(int n_1, int n_2, int N_1, int N_2) {
            this.n_1 = n_1;
            this.n_2 = n_2;
            this.N_1 = N_1;
            this.N_2 = N_2;
        }

        public void add(Result res) {
            this.n_1 += res.n_1;
            this.n_2 += res.n_2;
            this.N_1 += res.N_1;
            this.N_2 += res.N_2;
        }

        public String toString() {
            int programLength = N_1 + N_2;
            int programVocab = n_1 + n_2;
            double estimatedLength = n_1 * Math.log(n_1) + n_2 * Math.log(n_2);
            double volume = programLength * Math.log(programVocab);
            double difficulty = (double) n_1 / 2 * N_2 / 2;
            double effort = volume * difficulty;
            double timeToProgram = effort / 18;
            double deliveredBugs = volume / 3000;

            return String.format("""
                        Program Vocabulary (n): %15d
                            Program Length (N): %15d
                         Estimated Length (~N): %15.2f
                                    Volume (V): %15.2f
                                Difficulty (D): %15.2f
                                    Effort (E): %15.2f
                           Time to Program (T): %15.2f seconds
                            Delivered Bugs (B): %15.2f
                    """, programVocab, programLength, estimatedLength, volume, difficulty, effort, timeToProgram, deliveredBugs);
        }
    }

}
