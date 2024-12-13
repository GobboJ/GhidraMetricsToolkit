package impl;

import generic.stl.Pair;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphFactory;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public class McCabe {

    private static int countConnectedComponents(GDirectedGraph<String, GEdge<String>> graph) {
        int count = 0;
        Set<String> visited = new HashSet<>();
        Set<String> todo = new HashSet<>();

        for (String s : graph.getVertices()) {

            if (visited.contains(s)) {
                continue;
            }

            visited.add(s);
            todo.add(s);

            while (!todo.isEmpty()) {
                Iterator<String> i = todo.iterator();
                if (i.hasNext()) {
                    String u = i.next();
                    visited.add(u);
                    for (GEdge<String> ss : graph.getIncidentEdges(u)) {
                        if (!visited.contains(ss.getStart())) {
                            todo.add(ss.getStart());
                        }
                        if (!visited.contains(ss.getEnd())) {
                            todo.add(ss.getEnd());
                        }
                    }
                    todo.remove(u);
                }
            }
            count += 1;
        }
        return count;
    }

    public static int computeMcCabe(Program program) throws CancelledException {

        ConsoleTaskMonitor ctm = new ConsoleTaskMonitor();
        BasicBlockModel bbm = new BasicBlockModel(program);
        CodeBlockIterator bIter = bbm.getCodeBlocks(ctm);

        GDirectedGraph<String, GEdge<String>> graph = GraphFactory.createDirectedGraph();

        HashSet<String> vertices = new HashSet<>();

        for (CodeBlock block : bIter) {
            if (!vertices.contains(block.getName())) {
                vertices.add(block.getName());
                graph.addVertex(block.getName());
            }

            CodeBlockReferenceIterator bDestIter = block.getDestinations(ctm);

            while (bDestIter.hasNext()) {
                CodeBlockReference ref = bDestIter.next();
                if (ref.getFlowType().isCall()) {
                    continue;
                }
                String destName = ref.getDestinationBlock().getName();
                if (vertices.contains(destName)) {
                    vertices.add(destName);
                    graph.addVertex(destName);
                }

                graph.addEdge(new GEdge<>() {
                    @Override
                    public String getStart() {
                        return block.getName();
                    }

                    @Override
                    public String getEnd() {
                        return destName;
                    }
                });
            }
        }

        int nVertices = graph.getVertexCount();
        int nEdges = graph.getEdgeCount();
        int nComponents = countConnectedComponents(graph);

        int result = nEdges - nVertices + 2 * nComponents;
        // printf("Complexity[%s]: %d - %d + 2 * %d = %d\n", program.getName(), nEdges, nVertices, nComponents, result);
        return result;
    }

    public static ArrayList<Pair<String, Integer>> computeFunctions(Program program) throws CancelledException {

        ArrayList<Pair<String, Integer>> results = new ArrayList<>();
        CyclomaticComplexity cyclomaticComplexity = new CyclomaticComplexity();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        for (Function f : functions) {
            if (f.isThunk() || f.isExternal())
                continue;
            results.add(new Pair<>(f.getName(), cyclomaticComplexity.calculateCyclomaticComplexity(f, new ConsoleTaskMonitor())));
        }
        return results;
    }

}
