package impl.common;

import ghidra.program.model.listing.Program;

public interface SimilarityMetricFactory<T extends SimilarityInterface> {
    T create();
}
