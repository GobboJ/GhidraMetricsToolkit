# Ghidra Metrics

This Ghidra plugin provides a set of Software Metrics.
All the metrics can be computed through the GUI as well as through the script, even in headless mode.

## Installing

Download the latest release matching your Ghidra version and install it through the `File > Install Extensions` menu in the Ghidra tool launcher, or unzip the content in the `<GhidraInstallDir>/Ghidra/Extensions` folder.

The ROP Gadget Survival Similarity metric relies on `ROPGadget`, which must be installed with the `pip install ROPGadget`.

## Running

The GhidraMetrics GUI can be opened through the `Window > GhidraMetricsPlugin` menu in the CodeBrowser.

## Metrics

### McCabe Cyclomatic Complexity

This plugin provides a method to compute the overall McCabe Cyclomatic Complexity of the entire program, in addition to Ghidra's own `ghidra.program.util.CyclomaticComplexity` that computes it on a per-function basis.

### Entropy

The entropy is computed on the overall binary as well as on each program section. The base is customizable and defaulted to 2.

### Halstead Metrics

Halstead Metrics are provided both for the overall program and the currently highlighted function in the code listing. When using the GUI, both are computed automatically on every program or function change, while the headless script only computes it for the whole program.

### Longest Common Subsequence Similarity

Similarity metric based on the longest common subsequence size between the code listing of two functions. It lists the most similar function in the second program for each function in the first.

### Normalized Compression Distance Similarity

Compression based similarity metric. It uses the built-in `lrzip` binary to compress the programs, and is therefore only available on linux x86-64 platforms. It provides an overall similarity value as well as shows the most similar function in the second program for each function in the first.

### Opcode Frequency Histogram Similarity

Similarity metric that matches functions according to their opcode frequency histograms.

### ROP Gadget Survival Similarity

This metric computes the percentage of gadgets present in the first program that survive in the second program. More specifically, two variants are computed:

- Survivor: considers both the sequence of bytes of a gadget and its program offset;
- Bag of Gadgets: only considers the sequence of bytes, regardless of its position.

It is possible to set the maximum ROP depth search size in bytes, defaulted to 10.
