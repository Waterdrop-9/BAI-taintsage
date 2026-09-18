package com.bai.checkers;

import com.bai.Utils;
import com.bai.env.*;
import com.bai.env.region.Heap;
import com.bai.solver.PcodeVisitor;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.MemoryEvidenceExporter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import org.junit.Test;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class MemoryCorruptionStateTest extends ARMProgramTestBase {
    @Test public void offsetLoadAndStoreUseTheObjectLifetime() {
        Function owner = mock(Function.class);
        when(owner.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        Context context = mock(Context.class);
        when(context.getFunction()).thenReturn(owner);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        AbsEnv env = new AbsEnv();
        env.allocate(heap, new MemoryEvent(Utils.getDefaultAddress(0x1010), context, 0, "allocation"));
        env.release(heap, new MemoryEvent(Utils.getDefaultAddress(0x1020), context, 0, "release"), true);
        Varnode pointer = new Varnode(Utils.getRegisterAddress(0x20), 4);
        env.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(heap, heap.getBase() + 1)), true);
        Varnode space = new Varnode(Utils.getConstantAddress(0), 4);
        PcodeVisitor visitor = new PcodeVisitor(context);
        visitor.visit_LOAD(new PcodeOp(new SequenceNumber(Utils.getDefaultAddress(0x1030), 0), PcodeOp.LOAD,
                new Varnode[]{space, pointer}, new Varnode(Utils.getUniqueAddress(0x30), 1)), env, new AbsEnv());
        visitor.visit_STORE(new PcodeOp(new SequenceNumber(Utils.getDefaultAddress(0x1040), 0), PcodeOp.STORE,
                new Varnode[]{space, pointer, new Varnode(Utils.getConstantAddress(7), 1)}, null), env, new AbsEnv());
        assertEquals(2, MemoryEvidenceExporter.getCandidates().size());
        for (java.util.Map<String, Object> candidate : MemoryEvidenceExporter.getCandidates()) {
            assertEquals("CWE416", candidate.get("cwe"));
        }
    }

    @Test public void unknownCallDoesNotInventDereferenceAndScopesItsGap() {
        Function owner = mock(Function.class);
        when(owner.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        Context context = mock(Context.class);
        when(context.getFunction()).thenReturn(owner);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        Heap unrelated = Heap.getHeap(Utils.getDefaultAddress(0x1020), context);
        AbsEnv env = new AbsEnv();
        MemoryEvent allocation = new MemoryEvent(Utils.getDefaultAddress(0x1010), context, 0, "allocation");
        env.allocate(heap, allocation);
        env.allocate(unrelated, allocation);
        env.release(heap, new MemoryEvent(Utils.getDefaultAddress(0x1020), context, 0, "release"), true);
        Function callee = Utils.getMockFunction("opaque", new DataType[]{PointerDataType.dataType}, VoidDataType.dataType);
        when(callee.getName(false)).thenReturn("opaque");
        when(callee.getParameterCount()).thenReturn(1);
        when(callee.getSignatureSource()).thenReturn(ghidra.program.model.symbol.SourceType.ANALYSIS);
        env.set(ALoc.getALoc(callee.getParameter(0).getFirstStorageVarnode()), new KSet(32).insert(AbsVal.getPtr(heap)), true);
        MemoryCorruption.checkExternalCallParameters(Utils.getMockCallPcodeOp(), env, new AbsEnv(), context, callee);
        assertTrue(MemoryEvidenceExporter.getCandidates().isEmpty());
        assertTrue(env.getLifetime(heap).getGaps().contains("unmodeled_memory_effect:opaque"));
        assertFalse(env.getLifetime(unrelated).getGaps().contains("unmodeled_memory_effect:opaque"));
        assertTrue(env.getLifetime(unrelated).getGaps().isEmpty());
        assertFalse(MemoryEvidenceExporter.getAnalysisGaps().isEmpty());
    }
    @Test public void unregisteredHeapLoadReportsObjectCoverageWithoutInventingCandidate() {
        Function owner = mock(Function.class);
        when(owner.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        Context context = mock(Context.class);
        when(context.getFunction()).thenReturn(owner);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        AbsEnv env = new AbsEnv();
        Varnode pointer = new Varnode(Utils.getRegisterAddress(0x20), 4);
        env.set(ALoc.getALoc(pointer), new KSet(32).insert(AbsVal.getPtr(heap)), true);
        PcodeOp operation = new PcodeOp(new SequenceNumber(Utils.getDefaultAddress(0x1030), 0), PcodeOp.LOAD,
                new Varnode[]{new Varnode(Utils.getConstantAddress(0), 4), pointer},
                new Varnode(Utils.getUniqueAddress(0x30), 1));
        new PcodeVisitor(context).visit_LOAD(operation, env, new AbsEnv());
        assertTrue(MemoryEvidenceExporter.getCandidates().isEmpty());
        assertTrue(MemoryEvidenceExporter.getAnalysisGaps().stream().anyMatch(gap ->
                "allocation_state_missing".equals(gap.get("reason")) && "object".equals(gap.get("scope"))));
        assertTrue(env.getLifetime(heap).getGaps().contains("allocation_state_missing"));
    }

    @Test public void unregisteredHeapReleaseReportsObjectCoverageWithoutInventingCandidate() {
        Function owner = mock(Function.class);
        when(owner.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        Context context = mock(Context.class);
        when(context.getFunction()).thenReturn(owner);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        AbsEnv env = new AbsEnv();
        MemoryEvent release = new MemoryEvent(Utils.getDefaultAddress(0x1040), context, 0, "release");
        MemoryCorruption.checkDoubleFree(AbsVal.getPtr(heap), env, release, null, 0);
        assertTrue(MemoryEvidenceExporter.getCandidates().isEmpty());
        assertTrue(MemoryEvidenceExporter.getAnalysisGaps().stream().anyMatch(gap ->
                "allocation_state_missing".equals(gap.get("reason")) && "object".equals(gap.get("scope"))));
    }
}
