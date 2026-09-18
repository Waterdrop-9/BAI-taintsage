package com.bai.env;

import com.bai.Utils;
import com.bai.env.region.Heap;
import com.bai.solver.CFG;
import com.bai.solver.PcodeVisitor;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import org.mockito.MockedStatic;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class ContextLifetimeTest extends ARMProgramTestBase {
    @Test public void inputPartitionsRetainCounterAndLifetimeAssociation() {
        CFG cfg = mock(CFG.class);
        when(cfg.getSum()).thenReturn(1);
        Function function = mock(Function.class);
        var address = Utils.getDefaultAddress(0x1000);
        when(function.getEntryPoint()).thenReturn(address);
        try (MockedStatic<CFG> cfgFactory = mockStatic(CFG.class)) {
            cfgFactory.when(() -> CFG.getCFG(function)).thenReturn(cfg);
            Context context = Context.getEntryContext(function);
            Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
            MemoryEvent allocation = new MemoryEvent(Utils.getDefaultAddress(0x1010), context, 0, "allocation");
            MemoryEvent release = new MemoryEvent(Utils.getDefaultAddress(0x1020), context, 0, "release");
            ALoc counter = ALoc.getALoc(com.bai.env.region.Reg.getInstance(), 16, 4);
            AbsEnv initial = new AbsEnv();
            initial.set(counter, new KSet(32).insert(new AbsVal(0)), true);
            AbsEnv returned = new AbsEnv();
            returned.set(counter, new KSet(32).insert(new AbsVal(1)), true);
            returned.allocate(heap, allocation);
            returned.release(heap, release, true);
            assertTrue(context.propagateBefore(address, initial));
            assertTrue(context.propagateBefore(address, returned));
            assertFalse(context.propagateBefore(address, new AbsEnv(returned)));
            assertEquals(2, context.getStatesBefore(address).size());
            for (AbsEnv state : context.getStatesBefore(address)) {
                if (state.get(counter).equals(initial.get(counter))) {
                    assertNull(state.getLifetime(heap).getAllocation());
                } else {
                    assertFalse(state.getLifetime(heap).isMayLive());
                }
            }
            assertEquals(2, context.getValueBefore(address).get(counter).getInnerSet().size());
            assertEquals(context.getValueBefore(address), context.getAbsEnvIn().get(address));
        }
    }

    @Test public void sharedContextReturnsOnlyTheMatchingInput() {
        CFG cfg = mock(CFG.class);
        when(cfg.getSum()).thenReturn(1);
        Function function = mock(Function.class);
        var address = Utils.getDefaultAddress(0x1000);
        when(function.getEntryPoint()).thenReturn(address);
        try (MockedStatic<CFG> cfgFactory = mockStatic(CFG.class)) {
            cfgFactory.when(() -> CFG.getCFG(function)).thenReturn(cfg);
            Context context = Context.getEntryContext(function);
            ALoc flag = ALoc.getALoc(com.bai.env.region.Reg.getInstance(), 16, 4);
            Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
            AbsEnv keep = new AbsEnv();
            keep.allocate(heap, new MemoryEvent(Utils.getDefaultAddress(0x1010), context, 0, "allocation"));
            keep.set(flag, new KSet(32).insert(new AbsVal(0)), true);
            AbsEnv release = new AbsEnv(keep);
            release.set(flag, new KSet(32).insert(new AbsVal(1)), true);
            var keepCall = context.initContext(keep, false);
            var releaseCall = context.initContext(release, false);
            PcodeOp returned = new PcodeOp(new SequenceNumber(Utils.getDefaultAddress(0x1040), 0),
                    PcodeOp.RETURN, new Varnode[0], null);
            PcodeVisitor visitor = new PcodeVisitor(context);
            for (AbsEnv state : context.getStatesBefore(address)) {
                if (state.get(flag).equals(release.get(flag))) {
                    state.release(heap, new MemoryEvent(Utils.getDefaultAddress(0x1030), context, 0, "release"), true);
                    visitor.visit_RETURN(returned, state, new AbsEnv());
                }
            }
            assertNull(context.getExitValue(keepCall));
            assertFalse(context.getExitValue(releaseCall).getLifetime(heap).isMayLive());
            for (AbsEnv state : context.getStatesBefore(address)) {
                if (state.get(flag).equals(keep.get(flag))) {
                    visitor.visit_RETURN(returned, state, new AbsEnv());
                }
            }
            assertTrue(context.getExitValue(keepCall).getLifetime(heap).isMayLive());
            assertTrue(context.getExitValue(keepCall).getLifetime(heap).getReleases().isEmpty());
            assertFalse(context.getExitValue(releaseCall).getLifetime(heap).isMayLive());
        }
    }

    @Test public void returnsPreserveChangesWithIdenticalValueMaps() {
        CFG cfg = mock(CFG.class);
        when(cfg.getSum()).thenReturn(1);
        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        when(function.getName(false)).thenReturn("release_helper");
        try (MockedStatic<CFG> cfgFactory = mockStatic(CFG.class)) {
            cfgFactory.when(() -> CFG.getCFG(function)).thenReturn(cfg);
            Context context = Context.getEntryContext(function);
            Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
            MemoryEvent allocation = new MemoryEvent(Utils.getDefaultAddress(0x1010), context, 0, "allocation");
            MemoryEvent first = new MemoryEvent(Utils.getDefaultAddress(0x1020), context, 0, "release");
            MemoryEvent second = new MemoryEvent(Utils.getDefaultAddress(0x1030), context, 0, "release");
            AbsEnv before = new AbsEnv();
            before.allocate(heap, allocation);
            var invocation = context.initContext(before, false);
            AbsEnv entryState = context.getStatesBefore(function.getEntryPoint()).get(0);
            AbsEnv left = new AbsEnv(entryState);
            AbsEnv right = new AbsEnv(entryState);
            left.release(heap, first, true);
            right.release(heap, second, true);
            PcodeOp returned = new PcodeOp(new SequenceNumber(Utils.getDefaultAddress(0x1040), 0),
                    PcodeOp.RETURN, new Varnode[0], null);
            PcodeVisitor visitor = new PcodeVisitor(context);
            assertNull(context.getExitValue(invocation));
            visitor.visit_RETURN(returned, left, new AbsEnv());
            assertEquals(java.util.Set.of(first), context.getExitValue(invocation).getLifetime(heap).getReleases());
            visitor.visit_RETURN(returned, right, new AbsEnv());
            assertEquals(java.util.Set.of(first, second), context.getExitValue(invocation).getLifetime(heap).getReleases());
            AbsEnv caller = new AbsEnv(before);
            caller.applyLifetime(context.getExitValue(invocation));
            assertFalse(caller.getLifetime(heap).isMayLive());
            assertTrue(before.getLifetime(heap).isMayLive());
        }
    }
}
