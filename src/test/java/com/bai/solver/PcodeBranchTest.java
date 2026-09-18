package com.bai.solver;

import com.bai.Utils;
import com.bai.env.AbsEnv;
import com.bai.env.ALoc;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.GlobalState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import org.mockito.MockedStatic;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class PcodeBranchTest extends ARMProgramTestBase {
    @Test public void trueInstructionLocalConditionSelectsTakenSuccessor() {
        assertBranchSuccessors(new KSet(8).insert(new AbsVal(1)), true, false);
    }

    @Test public void falseInstructionLocalConditionSelectsFallthroughSuccessor() {
        assertBranchSuccessors(new KSet(8).insert(new AbsVal(0)), false, true);
    }

    @Test public void unknownInstructionLocalConditionRetainsBothSuccessors() {
        assertBranchSuccessors(KSet.getTop(), true, true);
    }

    private void assertBranchSuccessors(KSet value, boolean takesBranch, boolean fallsThrough) {
        var address = Utils.getDefaultAddress(0x1000);
        var taken = Utils.getDefaultAddress(0x1040);
        var fallthrough = Utils.getDefaultAddress(0x1004);
        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(address);
        Instruction instruction = mock(Instruction.class);
        Instruction next = mock(Instruction.class);
        when(next.getAddress()).thenReturn(fallthrough);
        Varnode condition = new Varnode(Utils.getUniqueAddress(0x80), 1);
        Varnode source = new Varnode(Utils.getRegisterAddress(0x20), 1);
        PcodeOp assign = new PcodeOp(new SequenceNumber(address, 0), PcodeOp.COPY,
                new Varnode[]{source}, condition);
        PcodeOp branch = new PcodeOp(new SequenceNumber(address, 1), PcodeOp.CBRANCH,
                new Varnode[]{new Varnode(taken, 4), condition}, null);
        when(instruction.getPcode(true)).thenReturn(new PcodeOp[]{assign, branch});
        FlatProgramAPI api = mock(FlatProgramAPI.class);
        when(api.getFunctionContaining(address)).thenReturn(function);
        when(api.getInstructionAt(address)).thenReturn(instruction);
        when(api.getInstructionAfter(address)).thenReturn(next);
        when(api.getAddressFactory()).thenReturn(program.getAddressFactory());
        GlobalState.flatAPI = api;
        CFG cfg = mock(CFG.class);
        when(cfg.getSum()).thenReturn(3);
        when(cfg.getWTOMap()).thenReturn(java.util.Map.of(address, 0, taken, 1, fallthrough, 2));
        try (MockedStatic<CFG> factory = mockStatic(CFG.class)) {
            factory.when(() -> CFG.getCFG(function)).thenReturn(cfg);
            Context context = Context.getEntryContext(function);
            AbsEnv environment = new AbsEnv();
            environment.set(ALoc.getALoc(source), value, true);
            new PcodeVisitor(context).visit(address, environment);
            assertEquals(takesBranch ? 1 : 0, context.getStatesBefore(taken).size());
            assertEquals(fallsThrough ? 1 : 0, context.getStatesBefore(fallthrough).size());
        }
    }
}
