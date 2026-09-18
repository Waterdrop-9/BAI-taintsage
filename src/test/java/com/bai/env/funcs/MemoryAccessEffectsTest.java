package com.bai.env.funcs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import org.junit.Test;
import static org.junit.Assert.*;

public class MemoryAccessEffectsTest extends ARMProgramTestBase {
    private Function function(String name, int parameters) {
        DataType[] types = new DataType[parameters];
        java.util.Arrays.fill(types, PointerDataType.dataType);
        return Utils.getMockFunction(name, types, IntegerDataType.dataType);
    }

    private void argument(AbsEnv env, Function function, int index, KSet value) {
        env.set(ALoc.getALoc(function.getParameter(index).getLastStorageVarnode()), value, true);
    }

    private void format(AbsEnv env, Function function, int index, String text) throws Exception {
        int transaction = program.startTransaction("format fixture");
        try {
            byte[] bytes = (text + "\u0000").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            programBuilder.createMemory(".format", "0x6000", 0x1000)
                    .putBytes(Utils.getDefaultAddress(0x6000), bytes);
        } finally {
            program.endTransaction(transaction, true);
        }
        argument(env, function, index, new KSet(32).insert(new AbsVal(0x6000)));
    }

    @Test
    public void distinguishesKnownNoAccessFromUnknown() {
        MemoryAccessEffects.Result known = MemoryAccessEffects.resolve(
                Utils.getMockCallPcodeOp(), new AbsEnv(), function("free", 1));
        assertTrue(known.isComplete());
        assertTrue(known.getAccesses().isEmpty());
        MemoryAccessEffects.Result unknown = MemoryAccessEffects.resolve(
                Utils.getMockCallPcodeOp(), new AbsEnv(), function("opaque", 1));
        assertFalse(unknown.isComplete());
        assertTrue(unknown.getAccesses().isEmpty());
    }

    @Test
    public void suppressesZeroLengthAndMarksUnknownLengthConditional() {
        Function memcpy = function("memcpy", 3);
        AbsEnv env = new AbsEnv();
        argument(env, memcpy, 2, new KSet(32).insert(new AbsVal(0)));
        assertTrue(MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, memcpy)
                .getAccesses().isEmpty());
        argument(env, memcpy, 2, new KSet(32).insert(new AbsVal(8)));
        MemoryAccessEffects.Result positive = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, memcpy);
        assertEquals(2, positive.getAccesses().size());
        assertEquals(0, positive.getAccesses().get(0).getArgumentIndex());
        assertEquals(MemoryAccessEffects.Kind.WRITE, positive.getAccesses().get(0).getKind());
        assertFalse(positive.getAccesses().get(0).isConditional());
        argument(env, memcpy, 2, KSet.getTop());
        assertTrue(MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, memcpy)
                .getAccesses().get(0).isConditional());
    }

    @Test
    public void distinguishesPrintedPointerStringAndCountStore() throws Exception {
        Function printf = function("printf", 4);
        AbsEnv env = new AbsEnv();
        format(env, printf, 0, "%p %s %n");
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertTrue(effects.getGaps().toString(), effects.isComplete());
        assertEquals(3, effects.getAccesses().size());
        assertEquals(0, effects.getAccesses().get(0).getArgumentIndex());
        assertEquals(2, effects.getAccesses().get(1).getArgumentIndex());
        assertEquals(MemoryAccessEffects.Kind.READ, effects.getAccesses().get(1).getKind());
        assertEquals(3, effects.getAccesses().get(2).getArgumentIndex());
        assertEquals(MemoryAccessEffects.Kind.WRITE, effects.getAccesses().get(2).getKind());
    }

    @Test
    public void unknownFormatRetainsKnownFormatAccessAndGap() {
        Function printf = function("printf", 1);
        AbsEnv env = new AbsEnv();
        argument(env, printf, 0, KSet.getTop());
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertFalse(effects.isComplete());
        assertEquals(1, effects.getAccesses().size());
        assertEquals(0, effects.getAccesses().get(0).getArgumentIndex());
    }

    @Test
    public void inputWritesAreConditionalAndZeroCountsHaveNoBufferEffect() {
        Function read = function("read", 3);
        AbsEnv env = new AbsEnv();
        argument(env, read, 2, new KSet(32).insert(new AbsVal(16)));
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, read);
        assertTrue(effects.isComplete());
        assertEquals(1, effects.getAccesses().size());
        assertTrue(effects.getAccesses().get(0).isConditional());
        assertEquals(1, effects.getAccesses().get(0).getArgumentIndex());
        argument(env, read, 2, new KSet(32).insert(new AbsVal(0)));
        assertTrue(MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, read).getAccesses().isEmpty());
    }

    @Test
    public void missingLengthSignatureIsAnExplicitGap() {
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(
                Utils.getMockCallPcodeOp(), new AbsEnv(), function("memcpy", 2));
        assertFalse(effects.isComplete());
        assertTrue(effects.getGaps().contains("missing_argument:2"));
        assertTrue(effects.getAccesses().get(0).isConditional());
    }

    @Test
    public void zeroPrecisionDoesNotDereferenceString() throws Exception {
        Function printf = function("printf", 3);
        AbsEnv env = new AbsEnv();
        format(env, printf, 0, "%% %.0s %p");
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertTrue(effects.isComplete());
        assertEquals(1, effects.getAccesses().size());
    }

    @Test
    public void unsupportedWidthDoesNotGuessArgumentPositions() throws Exception {
        Function printf = function("printf", 4);
        AbsEnv env = new AbsEnv();
        format(env, printf, 0, "%*s %n");
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertFalse(effects.isComplete());
        assertEquals(1, effects.getAccesses().size());
    }

    @Test
    public void zeroSnprintfCapacityRetainsFormatReadOnly() throws Exception {
        Function snprintf = function("snprintf", 3);
        AbsEnv env = new AbsEnv();
        format(env, snprintf, 2, "literal");
        argument(env, snprintf, 1, new KSet(32).insert(new AbsVal(0)));
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, snprintf);
        assertTrue(effects.isComplete());
        assertEquals(1, effects.getAccesses().size());
        assertEquals(2, effects.getAccesses().get(0).getArgumentIndex());
    }

    @Test
    public void zeroSnprintfCapacityStillReadsStringArguments() throws Exception {
        Function snprintf = function("snprintf", 4);
        AbsEnv env = new AbsEnv();
        format(env, snprintf, 2, "%s");
        argument(env, snprintf, 1, new KSet(32).insert(new AbsVal(0)));
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, snprintf);
        assertTrue(effects.isComplete());
        assertEquals(2, effects.getAccesses().size());
        assertEquals(2, effects.getAccesses().get(0).getArgumentIndex());
        assertEquals(3, effects.getAccesses().get(1).getArgumentIndex());
        assertTrue(effects.getAccesses().stream().allMatch(a -> a.getKind() == MemoryAccessEffects.Kind.READ));
    }

    @Test
    public void formatUsesCurrentAbstractMemoryRatherThanOriginalBinaryBytes() throws Exception {
        Function printf = function("printf", 2);
        AbsEnv env = new AbsEnv();
        format(env, printf, 0, "%p");
        env.set(ALoc.getALoc(Global.getInstance(), 0x6001, 1), new KSet(8).insert(new AbsVal('s')), true);
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertTrue(effects.isComplete());
        assertEquals(2, effects.getAccesses().size());
        assertEquals(1, effects.getAccesses().get(1).getArgumentIndex());
    }

    @Test
    public void unterminatedAbstractFormatIsNotTreatedAsComplete() {
        Function printf = function("printf", 2);
        AbsEnv env = new AbsEnv();
        argument(env, printf, 0, new KSet(32).insert(new AbsVal(0x7000)));
        env.set(ALoc.getALoc(Global.getInstance(), 0x7000, 1), new KSet(8).insert(new AbsVal('%')), true);
        env.set(ALoc.getALoc(Global.getInstance(), 0x7001, 1), new KSet(8).insert(new AbsVal('p')), true);
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(Utils.getMockCallPcodeOp(), env, printf);
        assertFalse(effects.isComplete());
        assertTrue(effects.getGaps().contains("unresolved_format"));
    }

    @Test
    public void resultCollectionsCannotBeMutated() {
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(
                Utils.getMockCallPcodeOp(), new AbsEnv(), function("puts", 1));
        assertThrows(UnsupportedOperationException.class, () -> effects.getAccesses().clear());
        assertThrows(UnsupportedOperationException.class, () -> effects.getGaps().add("changed"));
    }

    @Test
    public void partialInputModelKeepsKnownReadAndDoesNotClaimCompleteness() {
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(
                Utils.getMockCallPcodeOp(), new AbsEnv(), function("sscanf", 3));
        assertFalse(effects.isComplete());
        assertEquals(2, effects.getAccesses().size());
        assertTrue(effects.getAccesses().stream().allMatch(a -> a.getKind() == MemoryAccessEffects.Kind.READ));
    }
}
