package impl.common;

import generic.stl.Pair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;


public class SimilarityResult implements ResultInterface {

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

    private final Program program1;
    private final Program program2;

    private final List<Match> matches;
    public Double overallSimilarity;

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

    public void setOverallSimilarity(double overallSimilarity) {
        this.overallSimilarity = overallSimilarity;
    }

    public void calculateOverallSimilarity() {
        this.overallSimilarity = matches.stream().mapToDouble(m -> m.similarity).sum() / matches.size();
    }

    public List<Object[]> getMatches() {
        List<Object[]> s = new ArrayList<>();
        for (Match m : matches) {
            s.add(new Object[] {m.similarity, m.f1.getName(), m.f2.getName()});
        }
        return s;
    }

    @Override
    public List<Pair<String, String>> export() {

        List<Pair<String, String>> exportedData = new ArrayList<>();

        Pair<String, String> overallSimilarity = new Pair<>("Program 1,Program 2,Similarity",
                this.program1.getName() + "," + this.program2.getName() + "," + this.overallSimilarity);
        exportedData.add(overallSimilarity);

        StringBuilder functionSimilarityBuilder = new StringBuilder();
        for (var m : matches) {
            functionSimilarityBuilder
                    .append(m.f1.getName()).append(",")
                    .append(m.f2.getName()).append(",")
                    .append(m.similarity);
        }
        Pair<String, String> functionSimilarity = new Pair<>("Function 1,Function 2,Similarity", functionSimilarityBuilder.toString());
        exportedData.add(functionSimilarity);

        return exportedData;
    }

    @Override
    public String toString() {
        StringBuilder output = new StringBuilder();

        if (this.overallSimilarity != null) {
            output.append(String.format("Overall Similarity [%s, %s]: %f\n", program1.getName(), program2.getName(), overallSimilarity));
        }

        if (!this.matches.isEmpty()) {
            output.append("Function matching:\n");
            output.append(String.format("Sim  | %-26s | %-26s\n", program1.getName(), program2.getName()));
            output.append("--------------------------------------------------------------\n");
            for (Match m : matches) {
                output.append(String.format("%.2f | %-26s | %-26s \n", m.similarity, m.f1.getName(), m.f2.getName()));
            }
            output.append("--------------------------------------------------------------\n");
        }
        return output.toString();
    }

}