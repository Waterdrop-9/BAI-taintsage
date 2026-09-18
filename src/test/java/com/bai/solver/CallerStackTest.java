package com.bai.solver;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.MemoryEvent;
import com.bai.env.region.Heap;
import com.bai.env.region.Local;
import com.bai.util.Architecture;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.MemoryEvidenceExporter;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CallerStackTest extends AbstractGhidraHeadlessIntegrationTest {
    private Context context;
    private Local callee;
    private Local caller;
    private Local other;
    private Varnode pointer;
    private Varnode destination;
    private Varnode space;
    private SequenceNumber sequence;

    @Before public void setup() throws Exception {
        GlobalState.config = new Config();
        assertTrue(Logging.init());
        ProgramBuilder builder = new ProgramBuilder("CallerStack", "x86:LE:32:default");
        var program = builder.getProgram();
        int transaction = program.startTransaction("Create functions");
        Function calleeFunction;
        try {
            builder.createMemory(".text", "0x1000", 0x100).setExecute(true);
            var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            calleeFunction = program.getFunctionManager().createFunction("callee", address,
                    new AddressSet(address), SourceType.USER_DEFINED);
            var callerAddress = address.add(0x40);
            var otherAddress = address.add(0x80);
            Function callerFunction = program.getFunctionManager().createFunction("caller", callerAddress,
                    new AddressSet(callerAddress), SourceType.USER_DEFINED);
            Function otherFunction = program.getFunctionManager().createFunction("other", otherAddress,
                    new AddressSet(otherAddress), SourceType.USER_DEFINED);
            GlobalState.currentProgram = program;
            GlobalState.flatAPI = new FlatProgramAPI(program);
            GlobalState.reset();
            GlobalState.arch = new Architecture(program);
            callee = Local.getLocal(calleeFunction);
            caller = Local.getLocal(callerFunction);
            other = Local.getLocal(otherFunction);
        } finally {
            program.endTransaction(transaction, true);
        }
        CFG cfg = mock(CFG.class);
        when(cfg.getSum()).thenReturn(1);
        try (MockedStatic<CFG> factory = mockStatic(CFG.class)) {
            factory.when(() -> CFG.getCFG(calleeFunction)).thenReturn(cfg);
            context = Context.getEntryContext(calleeFunction);
        }
        pointer = new Varnode(Utils.getRegisterAddress(0), 4);
        destination = new Varnode(Utils.getRegisterAddress(8), 4);
        space = new Varnode(Utils.getConstantAddress(0), 4);
        sequence = new SequenceNumber(Utils.getDefaultAddress(0x1000), 0);
    }

    private PcodeOp load() {
        return new PcodeOp(sequence, PcodeOp.LOAD, new Varnode[] {space, pointer}, destination);
    }

    private PcodeOp store() {
        return new PcodeOp(sequence, PcodeOp.STORE,
                new Varnode[] {space, pointer, new Varnode(Utils.getConstantAddress(99), 4)}, null);
    }

    @Test public void multipleCallerMappingsWeaklyUpdateEveryPossibleCell() {
        AbsEnv state = new AbsEnv();
        state.setCallerStack(new KSet(32).insert(new AbsVal(caller, caller.getBase() + 16)).insert(new AbsVal(other, other.getBase() + 32)));
        state.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(callee, callee.getBase() + 4)), true);
        ALoc first = ALoc.getALoc(caller, caller.getBase() + 20, 4);
        ALoc second = ALoc.getALoc(other, other.getBase() + 36, 4);
        state.set(first, new KSet(32).insert(new AbsVal(1)), true);
        state.set(second, new KSet(32).insert(new AbsVal(2)), true);
        new PcodeVisitor(context).visit_STORE(store(), state, new AbsEnv());
        assertEquals(new KSet(32).insert(new AbsVal(1)).insert(new AbsVal(99)), state.get(first));
        assertEquals(new KSet(32).insert(new AbsVal(2)).insert(new AbsVal(99)), state.get(second));
    }

    @Test public void unknownCallerMappingLoadsTopAndRecordsCoverageGap() {
        AbsEnv state = new AbsEnv();
        state.setCallerStack(KSet.getTop());
        state.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(callee, callee.getBase() + 4)), true);
        state.set(ALoc.getALoc(callee, callee.getBase() + 4, 4), new KSet(32).insert(new AbsVal(17)), true);
        new PcodeVisitor(context).visit_LOAD(load(), state, new AbsEnv());
        assertTrue(state.get(ALoc.getALoc(destination)).isTop());
        assertFalse(MemoryEvidenceExporter.getAnalysisGaps().isEmpty());
    }

    @Test public void unknownCallerMappingInvalidatesPotentialStoreTargets() {
        AbsEnv state = new AbsEnv();
        state.setCallerStack(KSet.getTop());
        state.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(callee, callee.getBase() + 4)), true);
        ALoc first = ALoc.getALoc(caller, caller.getBase() + 20, 4);
        ALoc second = ALoc.getALoc(other, other.getBase() + 36, 4);
        ALoc invented = ALoc.getALoc(callee, callee.getBase() + 4, 4);
        state.set(first, new KSet(32).insert(new AbsVal(1)), true);
        state.set(second, new KSet(32).insert(new AbsVal(2)), true);
        new PcodeVisitor(context).visit_STORE(store(), state, new AbsEnv());
        assertTrue(state.get(first).isTop());
        assertTrue(state.get(second).isTop());
        assertFalse(state.get(invented).equals(new KSet(32).insert(new AbsVal(99))));
        assertFalse(MemoryEvidenceExporter.getAnalysisGaps().isEmpty());
    }

    @Test public void pointerAlreadyInCallerRegionIsNotRemappedOnLoad() {
        AbsEnv state = new AbsEnv();
        state.setCallerStack(new KSet(32).insert(new AbsVal(other, other.getBase() + 32)));
        state.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(caller, caller.getBase() + 4)), true);
        state.set(ALoc.getALoc(caller, caller.getBase() + 4, 4), new KSet(32).insert(new AbsVal(17)), true);
        state.set(ALoc.getALoc(other, other.getBase() + 36, 4), new KSet(32).insert(new AbsVal(88)), true);
        new PcodeVisitor(context).visit_LOAD(load(), state, new AbsEnv());
        assertEquals(new KSet(32).insert(new AbsVal(17)), state.get(ALoc.getALoc(destination)));
    }

    @Test public void pointerAlreadyInCallerRegionIsNotRemappedOnStore() {
        AbsEnv state = new AbsEnv();
        state.setCallerStack(new KSet(32).insert(new AbsVal(other, other.getBase() + 32)));
        state.set(ALoc.getALoc(pointer), new KSet(32).insert(new AbsVal(caller, caller.getBase() + 4)), true);
        ALoc original = ALoc.getALoc(caller, caller.getBase() + 4, 4);
        ALoc wrong = ALoc.getALoc(other, other.getBase() + 36, 4);
        state.set(original, new KSet(32).insert(new AbsVal(17)), true);
        state.set(wrong, new KSet(32).insert(new AbsVal(88)), true);
        new PcodeVisitor(context).visit_STORE(store(), state, new AbsEnv());
        assertEquals(new KSet(32).insert(new AbsVal(99)), state.get(original));
        assertEquals(new KSet(32).insert(new AbsVal(88)), state.get(wrong));
    }

    private record MixedTargets(AbsEnv state, Heap heap) { }

    private MixedTargets mixedReleasedTargets() {
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x2000), null);
        AbsVal target = new AbsVal(heap, heap.getBase());
        long localAddress = Integer.toUnsignedLong(target.hashCode() - callee.hashCode());
        if (localAddress < callee.getBase()) { localAddress += 1L << 32; }
        AbsVal local = new AbsVal(callee, localAddress);
        assertTrue(local.getOffset() >= 0);
        assertEquals(target.hashCode(), local.hashCode());
        KSet pointers = new KSet(32).insert(local).insert(target);
        if (!pointers.iterator().next().equals(local)) {
            pointers = new KSet(32).insert(target).insert(local);
        }
        assertEquals(local, pointers.iterator().next());
        AbsEnv state = new AbsEnv();
        state.setCallerStack(KSet.getTop());
        state.set(ALoc.getALoc(pointer), pointers, true);
        state.allocate(heap, new MemoryEvent(heap.getAllocAddress(), context, 0, "allocation"));
        state.release(heap, new MemoryEvent(Utils.getDefaultAddress(0x1004), context, 0, "release"), true);
        state.set(ALoc.getALoc(heap, heap.getBase(), 4), new KSet(32).insert(new AbsVal(17)), true);
        return new MixedTargets(state, heap);
    }

    @Test public void unresolvedLocalAlternativeDoesNotHideHeapUseAfterFreeLoad() {
        AbsEnv state = mixedReleasedTargets().state();
        new PcodeVisitor(context).visit_LOAD(load(), state, new AbsEnv());
        assertTrue(state.get(ALoc.getALoc(destination)).isTop());
        assertTrue(MemoryEvidenceExporter.getCandidates().stream()
                .anyMatch(candidate -> "use_after_free".equals(candidate.get("profile"))));
    }

    @Test public void unresolvedLocalAlternativeDoesNotSkipHeapStoreOrUseAfterFree() {
        MixedTargets targets = mixedReleasedTargets();
        AbsEnv state = targets.state();
        Heap heap = targets.heap();
        new PcodeVisitor(context).visit_STORE(store(), state, new AbsEnv());
        assertEquals(new KSet(32).insert(new AbsVal(17)).insert(new AbsVal(99)),
                state.get(ALoc.getALoc(heap, heap.getBase(), 4)));
        assertTrue(MemoryEvidenceExporter.getCandidates().stream()
                .anyMatch(candidate -> "use_after_free".equals(candidate.get("profile"))));
    }

    @Test public void unknownCallerMappingReturnsTopStackPointer() {
        AbsEnv callerState = new AbsEnv();
        callerState.set(ALoc.getSPALoc(), KSet.getTop(), true);
        Context.Invocation invocation = context.initContext(callerState, false);
        AbsEnv state = new AbsEnv(callerState);
        state.setCallInputs(Set.of(invocation.input()));
        state.setCallerStack(KSet.getTop());
        state.set(ALoc.getSPALoc(), new KSet(32).insert(new AbsVal(callee, callee.getBase() + 4)), true);
        new PcodeVisitor(context).visit_RETURN(new PcodeOp(sequence, PcodeOp.RETURN, new Varnode[0], null),
                state, new AbsEnv());
        assertTrue(context.getExitValue(invocation).get(ALoc.getSPALoc()).isTop());
        assertFalse(MemoryEvidenceExporter.getAnalysisGaps().isEmpty());
    }
}
