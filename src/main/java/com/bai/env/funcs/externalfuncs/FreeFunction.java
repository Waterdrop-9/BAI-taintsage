// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.env.funcs.externalfuncs;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.MemoryEvent;
import com.bai.env.region.Heap;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

/**
 * void free(void *ptr) <br>
 * delete <br>
 * delete[]
 */
public class FreeFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("free", "operator.delete", "operator.delete[]");

    public FreeFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        setReturnType(VoidDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        releasePointers(getParamKSet(callFunc, 0, inOutEnv), inOutEnv, MemoryEvent.at(pcode, context, "release"));
    }

    public static void releasePointers(KSet pointers, AbsEnv inOutEnv, MemoryEvent event) {
        if (!pointers.isNormal()) {
            inOutEnv.markUnresolvedEffect("unresolved_release_target", event);
            return;
        }
        for (AbsVal pointer : pointers) {
            if (!pointer.getRegion().isHeap()) { continue; }
            Heap heap = (Heap) pointer.getRegion();
            if (pointer.isBigVal() || pointer.getOffset() != 0) {
                inOutEnv.markHeapGap(heap, "invalid_interior_release", event);
                continue;
            }
            inOutEnv.release(heap, event, pointers.isSingleton());
        }
    }
}
