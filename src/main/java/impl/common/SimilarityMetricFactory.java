package impl.common;

import ghidra.program.model.listing.Program;

public interface SimilarityMetricFactory<T extends MetricInterface> {
    T create(Program program1, Program program2);
}
