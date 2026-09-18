package com.bai.env;

import com.bai.Utils;
import com.bai.checkers.MemoryCorruption;
import com.bai.env.funcs.MemoryEffectScope;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.region.Global;
import com.bai.env.region.Heap;
import com.bai.env.region.Local;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.util.List;
import java.util.Set;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MemoryCoverageTest extends ARMProgramTestBase {
    @Before
    public void initializeModels() { FunctionModelManager.initAll(); }

    private Heap allocate(AbsEnv env, long address) {
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(address), null);
        env.allocate(heap, new MemoryEvent(Utils.getDefaultAddress(address), null, 0, "allocation"));
        return heap;
    }

    private KSet pointer(com.bai.env.region.RegionBase region, long offset) {
        return new KSet(32).insert(new AbsVal(region, region.getBase() + offset));
    }

    private Function function(String name, int count) {
        DataType[] types = new DataType[count];
        java.util.Arrays.fill(types, PointerDataType.dataType);
        Function function = Utils.getMockFunction(name, types, IntegerDataType.dataType);
        when(function.getName(false)).thenReturn(name);
        when(function.getParameterCount()).thenReturn(count);
        when(function.getSignatureSource()).thenReturn(SourceType.ANALYSIS);
        return function;
    }

    @Test
    public void scopeFollowsHeapLocalAndGlobalFieldsWithoutAddingUnreachableHeap() {
        AbsEnv env = new AbsEnv();
        Heap box = allocate(env, 0x1100);
        Heap child = allocate(env, 0x1200);
        Heap independent = allocate(env, 0x1300);
        Heap global = allocate(env, 0x1400);
        Local stack = Local.getLocal(function("owner", 0));
        env.set(ALoc.getALoc(box, box.getBase() + 8, 4), pointer(child, 0), true);
        env.set(ALoc.getALoc(child, child.getBase(), 4), pointer(box, 0), true);
        env.set(ALoc.getALoc(stack, stack.getBase() - 16, 4), pointer(box, 0), true);
        env.set(ALoc.getALoc(Global.getInstance(), 0x7000, 4), pointer(global, 0), true);
        MemoryEffectScope.Result scope = MemoryEffectScope.resolve(env, List.of(pointer(stack, -16)), Set.of());
        assertEquals(Set.of(box, child, global), scope.getHeaps());
        assertFalse(scope.getHeaps().contains(independent));
        assertFalse(scope.isUnresolved());
    }

    @Test
    public void unknownFieldsAndUnknownRootRemainExplicit() {
        AbsEnv env = new AbsEnv();
        Heap box = allocate(env, 0x1100);
        env.set(ALoc.getALoc(box, box.getBase() + 8, 4), KSet.getTop(), true);
        assertTrue(MemoryEffectScope.resolve(env, List.of(pointer(box, 0)), Set.of()).isUnresolved());
        assertTrue(MemoryEffectScope.resolve(env, List.of(KSet.getTop()), Set.of()).isUnresolved());
    }

    @Test
    public void previouslyEscapedObjectIsReachableWithoutCurrentArguments() {
        AbsEnv env = new AbsEnv();
        Heap escaped = allocate(env, 0x1100);
        Heap child = allocate(env, 0x1200);
        env.set(ALoc.getALoc(escaped, escaped.getBase() + 8, 4), pointer(child, 0), true);
        assertEquals(Set.of(escaped, child), MemoryEffectScope.resolve(env, List.of(), Set.of(escaped)).getHeaps());
    }

    @Test
    public void fullyKnownOpaqueCallDoesNotPolluteIndependentObject() {
        AbsEnv env = new AbsEnv();
        Heap argument = allocate(env, 0x1100);
        Heap global = allocate(env, 0x1200);
        Heap independent = allocate(env, 0x1300);
        Function opaque = function("opaque", 1);
        env.set(ALoc.getALoc(opaque.getParameter(0).getLastStorageVarnode()), pointer(argument, 0), true);
        env.set(ALoc.getALoc(Global.getInstance(), 0x7000, 4), pointer(global, 0), true);
        MemoryCorruption.checkExternalCallParameters(Utils.getMockCallPcodeOp(), env, new AbsEnv(), null, opaque);
        assertFalse(env.getLifetime(argument).getGaps().isEmpty());
        assertFalse(env.getLifetime(global).getGaps().isEmpty());
        assertTrue(env.getLifetime(independent).getGaps().toString(), env.getLifetime(independent).getGaps().isEmpty());
    }

    @Test
    public void freshAllocationDoesNotInheritPastUnresolvedGap() {
        AbsEnv env = new AbsEnv();
        Heap before = allocate(env, 0x1100);
        env.markUnresolvedEffect("unresolved_indirect_call", new MemoryEvent(Utils.getDefaultAddress(0x1500), null, 0, "gap"));
        Heap after = allocate(env, 0x1200);
        assertFalse(env.getLifetime(before).getGaps().isEmpty());
        assertTrue(env.getLifetime(after).getGaps().toString(), env.getLifetime(after).getGaps().isEmpty());
    }

    @Test
    public void defaultSignatureDoesNotProveAnUnknownCallHasNoArguments() {
        AbsEnv env = new AbsEnv();
        Heap existing = allocate(env, 0x1100);
        Function opaque = function("opaque", 0);
        when(opaque.getSignatureSource()).thenReturn(SourceType.DEFAULT);
        MemoryCorruption.checkExternalCallParameters(Utils.getMockCallPcodeOp(), env, new AbsEnv(), null, opaque);
        assertTrue(env.getLifetime(existing).getGaps().stream().anyMatch(reason -> reason.startsWith("unresolved_scope:")));
        Heap fresh = allocate(env, 0x1200);
        assertTrue(env.getLifetime(fresh).getGaps().isEmpty());
    }

    @Test
    public void conditionalReadDoesNotPermanentlyPolluteLifetime() {
        AbsEnv env = new AbsEnv();
        Heap heap = allocate(env, 0x1100);
        Function read = function("read", 3);
        env.set(ALoc.getALoc(read.getParameter(1).getLastStorageVarnode()), pointer(heap, 0), true);
        env.set(ALoc.getALoc(read.getParameter(2).getLastStorageVarnode()), new KSet(32).insert(new AbsVal(8)), true);
        MemoryCorruption.checkExternalCallParameters(Utils.getMockCallPcodeOp(), env, new AbsEnv(), null, read);
        assertTrue(env.getLifetime(heap).getGaps().isEmpty());
        env.release(heap, new MemoryEvent(Utils.getDefaultAddress(0x1500), null, 0, "release"), true);
        assertTrue(env.getLifetime(heap).getGaps().isEmpty());
    }
}
