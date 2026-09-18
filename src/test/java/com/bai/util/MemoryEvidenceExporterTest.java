package com.bai.util;

import com.bai.Utils;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.MemoryEvent;
import com.bai.env.region.Heap;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MemoryEvidenceExporterTest {
    private final GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    private Context context;
    private Function callee;

    @Before public void setup() {
        GlobalState.config = new Config();
        assertTrue(Logging.init());
        Utils.mockArchitecture(true);
        Heap.resetPool();
        MemoryEvidenceExporter.reset();
        Logging.resetReports();
        GlobalState.flatAPI = mock(FlatProgramAPI.class);
        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(ram.getAddress(0x1000));
        when(function.getName(false)).thenReturn("owner");
        when(GlobalState.flatAPI.getFunctionContaining(any())).thenReturn(function);
        when(GlobalState.flatAPI.toAddr(anyLong())).thenAnswer(call -> ram.getAddress((long) call.getArgument(0)));
        context = mock(Context.class);
        when(context.getFunction()).thenReturn(function);
        when(context.getFuncs()).thenReturn(new Function[] {function});
        when(context.getCallString()).thenReturn(new long[] {0x900});
        callee = mock(Function.class);
        when(callee.getName(false)).thenReturn("free");
    }

    @Test public void retainsObjectsAndReleaseOriginsDespiteSameLogLocation() {
        AbsEnv env = new AbsEnv();
        MemoryEvent first = new MemoryEvent(ram.getAddress(0x1020), context, 0, "release");
        MemoryEvent terminal = new MemoryEvent(ram.getAddress(0x1030), context, 1, "release");
        for (long allocation : new long[] {0x1001, 0x1002}) {
            Heap heap = Heap.getHeap(ram.getAddress(allocation), context);
            env.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation"));
            env.release(heap, first, true);
            MemoryEvidenceExporter.record("CWE415", heap, env.getLifetime(heap), terminal, callee, 0, "release");
            MemoryEvidenceExporter.record("CWE415", heap, env.getLifetime(heap), terminal, callee, 0, "release");
        }
        List<Map<String, Object>> candidates = MemoryEvidenceExporter.getCandidates();
        assertEquals(2, candidates.size());
        assertNotEquals(candidates.get(0).get("candidate_id"), candidates.get(1).get("candidate_id"));
        Logging.report(new CWEReport("CWE415", "1", "first object").setAddress(terminal.getAddress()));
        Logging.report(new CWEReport("CWE415", "1", "second object").setAddress(terminal.getAddress()));
        assertEquals(1, Logging.getCWEReports().size());
        assertEquals(2, MemoryEvidenceExporter.getCandidates().size());
    }

    @Test public void retainsBothReleaseOriginsAndCompleteStrongerEvidence() {
        Heap heap = Heap.getHeap(ram.getAddress(0x1001), context);
        AbsEnv original = new AbsEnv();
        original.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation"));
        AbsEnv left = new AbsEnv(original);
        AbsEnv right = new AbsEnv(original);
        left.release(heap, new MemoryEvent(ram.getAddress(0x1010), context, 0, "release"), true);
        right.release(heap, new MemoryEvent(ram.getAddress(0x1020), context, 0, "release"), true);
        AbsEnv joined = left.join(right);
        MemoryEvent use = new MemoryEvent(ram.getAddress(0x1030), context, 2, "read");
        MemoryEvidenceExporter.record("CWE416", heap, joined.getLifetime(heap), use, null, -1, "read");
        assertEquals(2, MemoryEvidenceExporter.getCandidates().size());
        joined.markHeapGap(heap, "unknown_call");
        MemoryEvidenceExporter.record("CWE416", heap, joined.getLifetime(heap), use, null, -1, "read");
        assertEquals(2, MemoryEvidenceExporter.getCandidates().size());
        for (Map<String, Object> candidate : MemoryEvidenceExporter.getCandidates()) {
            assertEquals(List.of(), candidate.get("unknown_reasons"));
            assertEquals("use_after_free", candidate.get("profile"));
            List<?> events = (List<?>) candidate.get("events");
            Map<?, ?> terminal = (Map<?, ?>) events.get(1);
            assertEquals(Map.of("kind", "memory_operand", "opcode", "LOAD", "operand_index", 1), terminal.get("query"));
        }
        MemoryEvidenceExporter.reset();
        assertTrue(MemoryEvidenceExporter.getCandidates().isEmpty());
    }

    @Test public void completeWitnessSelectionIsOrderIndependentWithoutErasingCoverage() {
        Heap heap = Heap.getHeap(ram.getAddress(0x1001), context);
        MemoryEvent allocation = new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation");
        MemoryEvent first = new MemoryEvent(ram.getAddress(0x1020), context, 0, "release");
        MemoryEvent terminal = new MemoryEvent(ram.getAddress(0x1030), context, 1, "release");
        AbsEnv precise = new AbsEnv();
        precise.allocate(heap, allocation);
        precise.release(heap, first, true);
        AbsEnv uncertain = new AbsEnv(precise);
        uncertain.markHeapGap(heap, "unknown_call", terminal);
        MemoryEvidenceExporter.record("CWE415", heap, uncertain.getLifetime(heap), terminal, callee, 0, "release");
        MemoryEvidenceExporter.record("CWE415", heap, precise.getLifetime(heap), terminal, callee, 0, "release");
        List<Map<String, Object>> expected = MemoryEvidenceExporter.getCandidates();
        assertEquals(List.of(), expected.get(0).get("unknown_reasons"));
        assertEquals(1, MemoryEvidenceExporter.getAnalysisGaps().size());
        MemoryEvidenceExporter.reset();
        MemoryEvidenceExporter.record("CWE415", heap, precise.getLifetime(heap), terminal, callee, 0, "release");
        uncertain.markHeapGap(heap, "unknown_call", terminal);
        MemoryEvidenceExporter.record("CWE415", heap, uncertain.getLifetime(heap), terminal, callee, 0, "release");
        assertEquals(expected, MemoryEvidenceExporter.getCandidates());
        assertEquals(1, MemoryEvidenceExporter.getAnalysisGaps().size());
    }

    @Test public void incomparableEvidenceRemainsOneWholeWitness() {
        Heap heap = Heap.getHeap(ram.getAddress(0x1001), context);
        MemoryEvent first = new MemoryEvent(ram.getAddress(0x1020), context, 0, "release");
        MemoryEvent terminal = new MemoryEvent(ram.getAddress(0x1030), context, 1, "release");
        AbsEnv left = new AbsEnv();
        left.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation"));
        left.release(heap, first, true);
        left.markHeapGap(heap, "left_gap");
        AbsEnv right = new AbsEnv();
        right.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 1, "allocation"));
        right.release(heap, first, true);
        right.markHeapGap(heap, "right_gap");
        MemoryEvidenceExporter.record("CWE415", heap, left.getLifetime(heap), terminal, callee, 0, "release");
        var leftWitness = MemoryEvidenceExporter.getCandidates().get(0);
        MemoryEvidenceExporter.reset();
        MemoryEvidenceExporter.record("CWE415", heap, right.getLifetime(heap), terminal, callee, 0, "release");
        var rightWitness = MemoryEvidenceExporter.getCandidates().get(0);
        MemoryEvidenceExporter.record("CWE415", heap, left.getLifetime(heap), terminal, callee, 0, "release");
        var selected = MemoryEvidenceExporter.getCandidates().get(0);
        assertTrue(selected.equals(leftWitness) || selected.equals(rightWitness));
        MemoryEvidenceExporter.reset();
        MemoryEvidenceExporter.record("CWE415", heap, left.getLifetime(heap), terminal, callee, 0, "release");
        MemoryEvidenceExporter.record("CWE415", heap, right.getLifetime(heap), terminal, callee, 0, "release");
        assertEquals(selected, MemoryEvidenceExporter.getCandidates().get(0));
    }

    @Test public void scopedGapUsesTheSameObjectIdentityAsItsCandidate() {
        Heap heap = Heap.getHeap(ram.getAddress(0x1001), context);
        AbsEnv env = new AbsEnv();
        env.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation"));
        MemoryEvent first = new MemoryEvent(ram.getAddress(0x1020), context, 0, "release");
        env.release(heap, first, true);
        MemoryEvidenceExporter.recordGap("unknown_call", heap, first);
        MemoryEvidenceExporter.record("CWE415", heap, env.getLifetime(heap),
                new MemoryEvent(ram.getAddress(0x1030), context, 1, "release"), callee, 0, "release");
        Map<?, ?> object = (Map<?, ?>) MemoryEvidenceExporter.getCandidates().get(0).get("object");
        assertEquals(object.get("object_id"), MemoryEvidenceExporter.getAnalysisGaps().get(0).get("object_id"));
        MemoryEvidenceExporter.recordGap("indirect_target_unknown", null, first);
        assertTrue(MemoryEvidenceExporter.getAnalysisGaps().stream().anyMatch(gap ->
                "unresolved".equals(gap.get("scope")) && "".equals(gap.get("object_id"))));
    }
}
