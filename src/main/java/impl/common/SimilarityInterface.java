package impl.common;

import ghidra.program.model.listing.Program;

public interface SimilarityInterface {

    SimilarityResult computeSimilarity(Program p1, Program p2) throws Exception;
}
