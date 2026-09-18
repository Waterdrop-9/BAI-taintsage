package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Test;
import org.mockito.Mockito;

public class ReallocFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvoke() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockRealloc = Utils.getMockFunction("realloc",
                new DataType[]{PointerDataType.dataType, IntegerDataType.dataType}, PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        Heap heap1 = Heap.getHeap(Utils.getDefaultAddress(0x1010), mockContext);
        Heap heap2 = Heap.getHeap(Utils.getDefaultAddress(0x1020), mockContext);
        inOutEnv.allocate(heap1, new com.bai.env.MemoryEvent(heap1.getAllocAddress(), mockContext, 0, "allocation"));
        inOutEnv.allocate(heap2, new com.bai.env.MemoryEvent(heap2.getAllocAddress(), mockContext, 0, "allocation"));
        Heap payload = Heap.getHeap(Utils.getDefaultAddress(0x1030), mockContext);
        KSet fieldValue = new KSet(32).insert(AbsVal.getPtr(payload));
        inOutEnv.set(ALoc.getALoc(heap1, heap1.getBase() + 4, 4), fieldValue, true);

        ALoc arg0ALoc = ALoc.getALoc(mockRealloc.getParameter(0).getFirstStorageVarnode());
        KSet argKSet = new KSet(32)
                .insert(AbsVal.getPtr(heap1))
                .insert(AbsVal.getPtr(heap2));
        inOutEnv.set(arg0ALoc, argKSet, true);

        ALoc r1ALoc = ALoc.getALoc(mockRealloc.getParameter(1).getFirstStorageVarnode());
        KSet sizeKSet = new KSet(32).insert(new AbsVal(0x400));
        inOutEnv.set(r1ALoc, sizeKSet, true);

        ExternalFunctionBase reallocFunc = new ReallocFunction();
        reallocFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockRealloc);

        assert inOutEnv.get(arg0ALoc).getInnerSet().size() == 2;
        assert inOutEnv.getLifetime(heap1).isMayLive();
        assert inOutEnv.getLifetime(heap1).getGaps().contains("realloc_result_lifetime_correlation");
        KSet ptrKSet = inOutEnv.get(arg0ALoc);
        for (AbsVal ptr : ptrKSet) {
            if (!ptr.getRegion().isHeap()) { assert ptr.getValue() == 0; continue; }
            Heap heap = (Heap) ptr.getRegion();
            assert heap.getSize() == 0x400;
            org.junit.Assert.assertEquals(fieldValue, inOutEnv.get(ALoc.getALoc(heap, heap.getBase() + 4, 4)));
        }

    }
    @Test public void unknownAndInteriorPointersClearStaleReturn() {
        PcodeOp operation = Utils.getMockCallPcodeOp();
        Context context = Mockito.mock(Context.class);
        Function function = Utils.getMockFunction("realloc",
                new DataType[]{PointerDataType.dataType, IntegerDataType.dataType}, PointerDataType.dataType);
        ghidra.program.model.pcode.Varnode returnNode = new ghidra.program.model.pcode.Varnode(Utils.getRegisterAddress(0x28), 4);
        Mockito.when(function.getReturn().getFirstStorageVarnode()).thenReturn(returnNode);
        ALoc result = ALoc.getALoc(returnNode);
        ALoc input = ALoc.getALoc(function.getParameter(0).getFirstStorageVarnode());
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        for (KSet argument : java.util.List.of(KSet.getTop(), new KSet(32).insert(new AbsVal(heap, heap.getBase() + 1)))) {
            AbsEnv env = new AbsEnv();
            env.allocate(heap, com.bai.env.MemoryEvent.at(operation, context, "allocation"));
            env.set(input, argument, true);
            env.set(result, new KSet(32).insert(new AbsVal(0x1234)), true);
            new ReallocFunction().invoke(operation, env, new AbsEnv(), context, function);
            org.junit.Assert.assertTrue(env.get(result).isTop());
            org.junit.Assert.assertTrue(env.getLifetime(heap).isMayLive());
        }
    }

    @Test public void missingReturnBindingRecordsTheSkippedEffect() {
        PcodeOp operation = Utils.getMockCallPcodeOp();
        Context context = Mockito.mock(Context.class);
        Function function = Utils.getMockFunction("realloc",
                new DataType[]{PointerDataType.dataType, IntegerDataType.dataType}, PointerDataType.dataType);
        Mockito.when(function.getReturn().getFirstStorageVarnode()).thenReturn(null);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1010), context);
        AbsEnv env = new AbsEnv();
        env.allocate(heap, com.bai.env.MemoryEvent.at(operation, context, "allocation"));
        new ReallocFunction().invoke(operation, env, new AbsEnv(), context, function);
        org.junit.Assert.assertTrue(env.getLifetime(heap).getGaps().contains("unresolved_scope:realloc_return_binding_missing"));
        org.junit.Assert.assertTrue(com.bai.util.MemoryEvidenceExporter.getAnalysisGaps().stream()
                .anyMatch(gap -> "realloc_return_binding_missing".equals(gap.get("reason"))));
    }
}
