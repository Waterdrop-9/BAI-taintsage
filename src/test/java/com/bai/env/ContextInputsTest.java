package com.bai.env;

import com.bai.Utils;
import com.bai.env.region.Heap;
import com.bai.env.region.Local;
import com.bai.env.region.Reg;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class ContextInputsTest extends ARMProgramTestBase {
    private ALoc value;
    private Local firstStack;
    private Local secondStack;
    private Heap heap;
    private MemoryEvent allocation;
    private MemoryEvent release;

    @Before public void prepareInputs() throws Exception {
        value = ALoc.getALoc(Reg.getInstance(), 16, 4);
        int transaction = program.startTransaction("Create caller functions");
        try {
            var first = Utils.getDefaultAddress(0x1000);
            var second = Utils.getDefaultAddress(0x1040);
            Function firstFunction = program.getFunctionManager().createFunction("first", first,
                    new AddressSet(first), SourceType.USER_DEFINED);
            Function secondFunction = program.getFunctionManager().createFunction("second", second,
                    new AddressSet(second), SourceType.USER_DEFINED);
            firstStack = Local.getLocal(firstFunction);
            secondStack = Local.getLocal(secondFunction);
        } finally {
            program.endTransaction(transaction, true);
        }
        heap = Heap.getHeap(Utils.getDefaultAddress(0x1080), null);
        allocation = new MemoryEvent(Utils.getDefaultAddress(0x1080), null, 0, "allocation");
        release = new MemoryEvent(Utils.getDefaultAddress(0x1084), null, 0, "release");
    }

    @Test public void exactInputsKeepIndependentExitLifetimes() {
        ContextInputs inputs = new ContextInputs(4);
        AbsEnv keep = new AbsEnv();
        keep.allocate(heap, allocation);
        keep.set(value, new KSet(32).insert(new AbsVal(0)), true);
        AbsEnv freeing = new AbsEnv(keep);
        freeing.set(value, new KSet(32).insert(new AbsVal(1)), true);
        int keepId = inputs.register(keep);
        int freeId = inputs.register(freeing);
        assertNotEquals(keepId, freeId);
        freeing.setCallInputs(Set.of(freeId));
        freeing.release(heap, release, true);
        assertTrue(inputs.returnFrom(freeing));
        assertNull(inputs.getExit(keepId));
        assertFalse(inputs.getExit(freeId).getLifetime(heap).isMayLive());
        keep.setCallInputs(Set.of(keepId));
        assertTrue(inputs.returnFrom(keep));
        assertTrue(inputs.getExit(keepId).getLifetime(heap).getReleases().isEmpty());
        assertFalse(inputs.returnFrom(new AbsEnv(keep)));
        AbsEnv detached = inputs.getExit(keepId);
        detached.release(heap, release, true);
        assertTrue(inputs.getExit(keepId).getLifetime(heap).getReleases().isEmpty());
    }

    @Test public void callerPropagationIdsDoNotChangeRegistrationIdentity() {
        ContextInputs inputs = new ContextInputs(4);
        AbsEnv first = new AbsEnv();
        first.setCallInputs(Set.of(7));
        first.set(value, new KSet(32).insert(new AbsVal(3)), true);
        int identity = inputs.register(first);
        AbsEnv second = new AbsEnv(first);
        second.setCallInputs(Set.of(11));
        assertEquals(identity, inputs.register(second));
        assertEquals(Set.of(7), first.getCallInputs());
        assertEquals(Set.of(11), second.getCallInputs());
    }

    @Test public void registeredEntrySnapshotSurvivesCallerMutation() {
        ContextInputs inputs = new ContextInputs(4);
        AbsEnv caller = new AbsEnv();
        caller.allocate(heap, allocation);
        caller.set(ALoc.getSPALoc(), new KSet(32).insert(new AbsVal(firstStack, 16)), true);
        AbsEnv original = new AbsEnv(caller);
        int identity = inputs.register(caller);
        caller.release(heap, release, true);
        caller.set(ALoc.getSPALoc(), new KSet(32).insert(new AbsVal(secondStack, 32)), true);
        assertEquals(identity, inputs.register(original));
        assertNotEquals(identity, inputs.register(caller));
        assertEquals(original.get(ALoc.getSPALoc()), inputs.getCallerStack(Set.of(identity), 32));
    }

    @Test public void nestedLifetimeTransferPreservesOuterCallInput() {
        ContextInputs nested = new ContextInputs(4);
        AbsEnv caller = new AbsEnv();
        caller.allocate(heap, allocation);
        caller.setCallInputs(Set.of(41));
        int nestedId = nested.register(caller);
        AbsEnv returned = new AbsEnv(caller);
        returned.setCallInputs(Set.of(nestedId));
        returned.release(heap, release, true);
        assertTrue(nested.returnFrom(returned));
        caller.applyLifetime(nested.getExit(nestedId));
        assertEquals(Set.of(41), caller.getCallInputs());
        assertFalse(caller.getLifetime(heap).isMayLive());
        assertTrue(nested.getExit(nestedId).getCallInputs().isEmpty());
    }

    @Test public void overflowJoinsDifferentOutputsWithoutOverwritingExactInput() {
        ContextInputs inputs = new ContextInputs(1);
        AbsEnv exact = new AbsEnv();
        exact.set(value, new KSet(32).insert(new AbsVal(0)), true);
        int exactId = inputs.register(exact);
        AbsEnv first = new AbsEnv();
        first.set(value, new KSet(32).insert(new AbsVal(1)), true);
        int overflowId = inputs.register(first);
        AbsEnv second = new AbsEnv();
        second.set(value, new KSet(32).insert(new AbsVal(2)), true);
        assertEquals(overflowId, inputs.register(second));
        assertFalse(inputs.isOverflow(exactId));
        assertTrue(inputs.isOverflow(overflowId));
        first.setCallInputs(Set.of(overflowId));
        second.setCallInputs(Set.of(overflowId));
        assertTrue(inputs.returnFrom(first));
        assertTrue(inputs.returnFrom(second));
        assertEquals(new KSet(32).insert(new AbsVal(1)).insert(new AbsVal(2)), inputs.getExit(overflowId).get(value));
        assertNull(inputs.getExit(exactId));
        assertEquals(exactId, inputs.register(exact));
    }

    @Test public void callerStacksAreSelectedByInputAndOverflowRetainsBoth() {
        ContextInputs inputs = new ContextInputs(1);
        AbsEnv first = new AbsEnv();
        KSet firstSP = new KSet(32).insert(new AbsVal(firstStack, 16));
        first.set(ALoc.getSPALoc(), firstSP, true);
        int firstId = inputs.register(first);
        AbsEnv second = new AbsEnv();
        KSet secondSP = new KSet(32).insert(new AbsVal(secondStack, 32));
        second.set(ALoc.getSPALoc(), secondSP, true);
        int secondId = inputs.register(second);
        assertEquals(firstSP, inputs.getCallerStack(Set.of(firstId), 32));
        assertEquals(secondSP, inputs.getCallerStack(Set.of(secondId), 32));
        AbsEnv third = new AbsEnv();
        KSet thirdSP = new KSet(32).insert(new AbsVal(firstStack, 48));
        third.set(ALoc.getSPALoc(), thirdSP, true);
        assertEquals(secondId, inputs.register(third));
        assertEquals(secondSP.join(thirdSP), inputs.getCallerStack(Set.of(secondId), 32));
        assertEquals(firstSP, inputs.getCallerStack(Set.of(firstId), 32));
    }

    @Test public void mixedInputGapSurvivesReturnAndAppliesToLaterAllocations() {
        ContextInputs inputs = new ContextInputs(4);
        AbsEnv first = new AbsEnv();
        first.set(value, new KSet(32).insert(new AbsVal(0)), true);
        AbsEnv second = new AbsEnv();
        second.set(value, new KSet(32).insert(new AbsVal(1)), true);
        int firstId = inputs.register(first);
        int secondId = inputs.register(second);
        first.setCallInputs(Set.of(firstId));
        second.setCallInputs(Set.of(secondId));
        AbsEnv merged = first.join(second);
        assertTrue(inputs.returnFrom(merged));
        for (int id : new int[] {firstId, secondId}) {
            AbsEnv returned = inputs.getExit(id);
            returned.allocate(heap, allocation);
            assertTrue(returned.getLifetime(heap).getGaps().contains("call_input_correlation_lost"));
        }
    }

    @Test public void callerStackMetadataChangeReachesStatePartitionsWithoutChangingInputKey() {
        ContextInputs inputs = new ContextInputs(4);
        AbsEnv first = new AbsEnv();
        first.setCallInputs(Set.of(0));
        KSet firstSP = new KSet(32).insert(new AbsVal(firstStack, 16));
        KSet secondSP = new KSet(32).insert(new AbsVal(secondStack, 32));
        first.setCallerStack(firstSP);
        AbsEnv second = new AbsEnv(first);
        second.setCallerStack(secondSP);
        assertEquals(firstSP, first.getCallerStack());
        assertNotEquals(first, second);
        assertTrue(first.sameValues(second));
        assertEquals(inputs.register(first), inputs.register(second));
        AbsEnvPartitions partitions = new AbsEnvPartitions(4);
        assertTrue(partitions.add(first));
        assertTrue(partitions.add(second));
        assertFalse(partitions.add(new AbsEnv(second)));
        assertEquals(firstSP.join(secondSP), partitions.joined().getCallerStack());
    }
}
