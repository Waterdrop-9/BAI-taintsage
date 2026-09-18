package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import org.javimmutable.collections.JImmutableMap.Entry;

/**
 * void *realloc(void *ptr, size_t size)
 */
public class ReallocFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("realloc");

    public ReallocFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            inOutEnv.markUnresolvedEffect("realloc_return_binding_missing", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            return;
        }
        KSet ptrKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!ptrKSet.isNormal()) {
            inOutEnv.markUnresolvedEffect("unresolved_reallocation_target", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            inOutEnv.set(retALoc, KSet.getTop(), true);
            return;
        }
        AbsEnv success = new AbsEnv(inOutEnv);
        for (AbsVal pointer : ptrKSet) {
            if (!pointer.getRegion().isHeap()) { continue; }
            Heap heap = (Heap) pointer.getRegion();
            if (pointer.isBigVal() || pointer.getOffset() != 0) {
                inOutEnv.markHeapGap(heap, "invalid_interior_reallocation", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
                inOutEnv.set(retALoc, KSet.getTop(), true);
                return;
            }
            success.release(heap, com.bai.env.MemoryEvent.at(pcode, context, "release"), ptrKSet.isSingleton());
            success.markHeapGap(heap, "realloc_result_lifetime_correlation", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
        }
        AbsEnv merged = inOutEnv.join(success);
        if (merged != null) { inOutEnv.applyLifetime(merged); }
        long size = Heap.DEFAULT_SIZE;
        KSet sizeKSet = getParamKSet(callFunc, 1, inOutEnv);
        if (sizeKSet.isNormal()) {
            ArrayList<Long> sizeList = new ArrayList<>();
            for (AbsVal absVal : sizeKSet) {
                if (absVal.getRegion().isGlobal()) {
                    sizeList.add(absVal.getValue());
                }
            }
            size = sizeList.isEmpty() ? size : Collections.max(sizeList);
        }
        // If requested size is zero we skip the allocation part
        if (size == 0) {
            inOutEnv.markHeapGap("realloc_zero_size_semantics", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            inOutEnv.set(retALoc, KSet.getTop(), true);
            return;
        }
        Address allocAddress = getAddress(pcode);
        KSet resKSet = new KSet(retALoc.getLen() * 8);
        Heap allocChunk = Heap.getHeap(allocAddress, context, size);
        inOutEnv.allocate(allocChunk, com.bai.env.MemoryEvent.at(pcode, context, "allocation"));
        inOutEnv.markHeapGap(allocChunk, "realloc_result_lifetime_correlation", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
        boolean exactSize = sizeKSet.isNormal() && sizeKSet.isSingleton()
                && sizeKSet.iterator().next().getRegion().isGlobal()
                && !sizeKSet.iterator().next().isBigVal() && size > 0;
        if (!exactSize) {
            inOutEnv.markHeapGap(allocChunk, "realloc_content_extent_unknown", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
        }
        AbsEnv contents = new AbsEnv();
        for (AbsVal pointer : ptrKSet) {
            if (!pointer.getRegion().isHeap()) { continue; }
            Heap original = (Heap) pointer.getRegion();
            for (Entry<ALoc, KSet> entry : inOutEnv.getEnvMap()) {
                ALoc source = entry.getKey();
                if (!source.getRegion().equals(original)) { continue; }
                long offset = source.getBegin() - original.getBase();
                long extent = Math.min(size, original.getSize());
                if (offset < 0 || offset >= extent) { continue; }
                int length = (int) Math.min(source.getLen(), extent - offset);
                ALoc target = ALoc.getALoc(allocChunk, allocChunk.getBase() + offset, length);
                KSet value = inOutEnv.get(ALoc.getALoc(original, source.getBegin(), length));
                contents.set(target, value, false);
            }
        }
        for (Entry<ALoc, KSet> entry : contents.getEnvMap()) {
            inOutEnv.set(entry.getKey(), entry.getValue(), true);
        }
        resKSet = resKSet.insert(AbsVal.getPtr(allocChunk)).insert(new AbsVal(0));
        inOutEnv.set(retALoc, resKSet, true);
    }
}
