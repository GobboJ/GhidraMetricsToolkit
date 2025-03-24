package impl.metrics;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import impl.common.SimilarityInterface;
import org.apache.commons.text.similarity.JaccardSimilarity;
import org.apache.commons.text.similarity.SimilarityInput;

import java.util.ArrayList;
import java.util.List;

public class Jaccard implements SimilarityInterface {

    static class ListingInput implements SimilarityInput<String> {

        private final List<String> listing;

        public ListingInput(List<String> listing) {
            this.listing = listing;
        }

        @Override
        public String at(int i) {
            return listing.get(i);
        }

        @Override
        public int length() {
            return listing.size();
        }
    }

    private static List<String> getOpcodeListing(Function function) {
        List<String> listing = new ArrayList<>();
        for (CodeUnit cb : function.getProgram().getListing().getCodeUnits(function.getBody(), true)) {
            listing.add(cb.toString());
        }
        return listing;
    }

    @Override
    public double compute(Function function1, Function function2) {
        ListingInput listing1 = new ListingInput(getOpcodeListing(function1));
        ListingInput listing2 = new ListingInput(getOpcodeListing(function2));
        JaccardSimilarity jaccardSimilarity = new JaccardSimilarity();
        return jaccardSimilarity.apply(listing1, listing2);
    }
}
