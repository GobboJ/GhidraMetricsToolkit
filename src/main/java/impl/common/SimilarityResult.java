package impl.common;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;


public class SimilarityResult {

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
    private final Program program1;
    private final Program program2;

    public SimilarityResult(Program program1, Program program2) {
        this.program1 = program1;
        this.program2 = program2;
        matches = new ArrayList<>();
    }

    public void addMatch(Function f1, Function f2, double similarity) {
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

    public List<Object[]> getMatches() {
        List<Object[]> s = new ArrayList<>();
        for (Match m : matches) {
            s.add(new Object[] {m.similarity, m.f1.getName(), m.f2.getName()});
        }
        return s;
    }

    @Override
    public String toString() {
        StringBuilder output = new StringBuilder();
        output.append("Function matching:\n");
        output.append(String.format("Sim  | %-26s | %-26s\n", program1.getName(), program2.getName()));
        output.append("--------------------------------------------------------------\n");
        for (Match m : matches) {
            output.append(String.format("%.2f | %-26s | %-26s \n", m.similarity, m.f1.getName(), m.f2.getName()));
        }
        output.append("--------------------------------------------------------------\n");
        return output.toString();
    }

}