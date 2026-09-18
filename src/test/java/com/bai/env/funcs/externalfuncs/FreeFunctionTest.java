package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Test;
import org.mockito.Mockito;

public class FreeFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvoke() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockFree = Utils.getMockFunction("free", new DataType[]{PointerDataType.dataType},
                PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        ALoc arg0ALoc = ALoc.getALoc(mockFree.getParameter(0).getFirstStorageVarnode());
        KSet argKSet = new KSet(32)
                .insert(AbsVal.getPtr(Heap.getHeap(Utils.getDefaultAddress(0x1010), mockContext)))
                .insert(AbsVal.getPtr(Heap.getHeap(Utils.getDefaultAddress(0x1020), mockContext, 0)));

        inOutEnv.set(arg0ALoc, argKSet, true);
        ExternalFunctionBase freeFunc = new FreeFunction();
        freeFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockFree);
        KSet ptrKSet = inOutEnv.get(arg0ALoc);
        for (AbsVal ptr : ptrKSet) {
            Heap heap = (Heap) ptr.getRegion();
            assert !inOutEnv.getLifetime(heap).getReleases().isEmpty();
        }
    }
    @Test public void releasesObjectAcrossOffsetsWithoutRewritingAliases() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context context = Mockito.mock(Context.class);
        Function function = Utils.getMockFunction("free", new DataType[]{PointerDataType.dataType}, PointerDataType.dataType);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x4010), context);
        Heap separate = Heap.getHeap(Utils.getDefaultAddress(0x4020), context);
        AbsEnv env = new AbsEnv();
        env.allocate(heap, com.bai.env.MemoryEvent.at(pcode, context, "allocation"));
        env.allocate(separate, com.bai.env.MemoryEvent.at(pcode, context, "allocation"));
        ALoc argument = ALoc.getALoc(function.getParameter(0).getFirstStorageVarnode());
        ALoc field = ALoc.getALoc(separate, separate.getBase(), 4);
        KSet alias = new KSet(32).insert(new AbsVal(heap, heap.getBase() + 1));
        env.set(field, alias, true);
        env.set(argument, new KSet(32).insert(AbsVal.getPtr(heap)), true);
        new FreeFunction().invoke(pcode, env, new AbsEnv(), context, function);
        org.junit.Assert.assertEquals(alias, env.get(field));
        org.junit.Assert.assertFalse(env.getLifetime(heap).isMayLive());
        org.junit.Assert.assertTrue(env.getLifetime(separate).isMayLive());
    }

    @Test public void interiorReleaseDoesNotFreeBaseObject() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context context = Mockito.mock(Context.class);
        Function function = Utils.getMockFunction("free", new DataType[]{PointerDataType.dataType}, PointerDataType.dataType);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x5010), context);
        AbsEnv env = new AbsEnv();
        env.allocate(heap, com.bai.env.MemoryEvent.at(pcode, context, "allocation"));
        ALoc argument = ALoc.getALoc(function.getParameter(0).getFirstStorageVarnode());
        env.set(argument, new KSet(32).insert(new AbsVal(heap, heap.getBase() + 1)), true);
        new FreeFunction().invoke(pcode, env, new AbsEnv(), context, function);
        org.junit.Assert.assertTrue(env.getLifetime(heap).isMayLive());
        org.junit.Assert.assertTrue(env.getLifetime(heap).getReleases().isEmpty());
        org.junit.Assert.assertTrue(env.getLifetime(heap).getGaps().contains("invalid_interior_release"));
    }
}
