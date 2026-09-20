// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.MemoryEvent;
import com.bai.env.HeapLifetime;
import com.bai.env.funcs.MemoryAccessEffects;
import com.bai.env.funcs.MemoryEffectScope;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.VarArgsFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.MemoryEvidenceExporter;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.List;

/**
 * CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer <br>
 * CWE-125: Out-of-bounds Read <br>
 * CWE-415: Double Free <br>
 * CWE-416: Use After Free <br>
 * CWE-476: NULL Pointer Dereference <br>
 * CWE-787: Out-of-bounds Write <br>
 */
public class MemoryCorruption {

    public static final int TYPE_READ = 0;
    public static final int TYPE_WRITE = 1;
    public static final int TYPE_ARGS = 2;

    public static final String CWE119 = "CWE119"; // Buffer Overflow (Generic case)
    public static final String CWE125 = "CWE125"; // Out-of-bounds Read
    public static final String CWE415 = "CWE415"; // Double Free
    public static final String CWE416 = "CWE416"; // Use After Free
    public static final String CWE476 = "CWE476"; // NULL Pointer Dereference
    public static final String CWE787 = "CWE787"; // Out-of-bounds Write
    public static final String VERSION = "0.1";

    // Safe unit to write beyond recorded stack size, because it's not always accurate to get real stack size from SP,
    // this could reduce false positive of CWE787.
    private static int getSafeUnitCnt() {
        return GlobalState.arch.isX86() ? 1 : 0;
    }

    /**
     * @hidden
     * @param kSet
     * @param address
     * @param context
     * @param callee
     * @param type
     * @param argIndex
     * @return
     */
    public static boolean checkNullPointerDereference(KSet kSet, Address address, Context context, Function callee,
            int type, int argIndex) {
        if (!kSet.isNormal() || !kSet.isSingleton()) {
            return true;
        }
        AbsVal ptr = kSet.iterator().next();
        String details = null;
        if (ptr.getRegion().isGlobal() && ptr.isZero()) {
            switch (type) {
                case TYPE_READ:
                    details = "Null pointer dereference Read";
                    break;
                case TYPE_WRITE:
                    details = "Null pointer dereference Write";
                    break;
                case TYPE_ARGS:
                    details =
                            "Null pointer dereference when Call to \"" + callee.getName(false) + "\" at "
                                    + Utils.getOrdinal(argIndex + 1) + " argument";
                    break;
                default: // nothing
            }
            CWEReport report = new CWEReport(CWE476, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    /**
     * @hidden
     * @param ptr
     * @param address
     * @param context
     * @param callee
     * @param type
     * @return
     */
    public static boolean checkUseAfterFree(AbsVal pointer, AbsEnv env, MemoryEvent event,
            Function callee, int argumentIndex, int type, boolean conditional) {
        Heap heap = (Heap) pointer.getRegion();
        HeapLifetime state = env.getLifetime(heap);
        if (state.getGaps().contains("allocation_state_missing")) {
            env.markHeapGap(heap, "allocation_state_missing", event);
        }
        if (state.getReleases().isEmpty()) { return true; }
        if (conditional) { state = state.withGap("conditional_access_effect"); }
        String access = type == TYPE_WRITE ? "write" : "read";
        MemoryEvidenceExporter.record(CWE416, heap, state, event, callee, argumentIndex, access);
        Logging.report(new CWEReport(CWE416, VERSION, "Use After Free " + access
                + " for chunk allocated at " + heap.getAllocAddress())
                .setAddress(event.getAddress()).setContext(event.getContext()));
        return false;
    }

    public static boolean checkDoubleFree(AbsVal pointer, AbsEnv env, MemoryEvent event,
            Function callee, int argumentIndex) {
        Heap heap = (Heap) pointer.getRegion();
        HeapLifetime state = env.getLifetime(heap);
        if (state.getGaps().contains("allocation_state_missing")) {
            env.markHeapGap(heap, "allocation_state_missing", event);
        }
        if (pointer.isBigVal() || pointer.getOffset() != 0 || state.getReleases().isEmpty()) { return true; }
        MemoryEvidenceExporter.record(CWE415, heap, state, event, callee, argumentIndex, "release");
        Logging.report(new CWEReport(CWE415, VERSION, "Double Free for chunk allocated at " + heap.getAllocAddress())
                .setAddress(event.getAddress()).setContext(event.getContext()));
        return false;
    }

    private static boolean checkHeapOutOfBound(AbsVal ptr, Address address, Context context, Function callee,
            int type) {
        if (ptr.getOffset() < 0 || ptr.getOffset() >= ptr.getRegion().getSize()) {
            String details = null;
            String cwe = null;
            switch (type) {
                case TYPE_READ:
                    details = "Heap Out-of-Bound Read";
                    cwe = CWE125;
                    break;
                case TYPE_WRITE:
                    details = "Heap Out-of-Bound Write";
                    cwe = CWE787;
                    break;
                case TYPE_ARGS:
                    details = "Heap Out-of-Bound when Call to " + callee.getName(false);
                    cwe = CWE119;
                    break;
                default: // nothing
            }
            Logging.debug("Check OOB for: " + ptr + " at " + address.toString() + "," + context.toString());
            details += " for chunk allocated at " + ((Heap) ptr.getRegion()).getAllocAddress() + ", when access";
            CWEReport report = new CWEReport(cwe, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    private static boolean checkStackOutOfBound(AbsVal ptr, Address address, Context context, Function callee,
            int type) {

        long offset = ptr.getOffset();
        if (Utils.isLeafFunction(context.getFunction()) && offset < 0) {
            // suppress false positive on leaf function
            return true;
        }
        if (offset >= 0 && type != TYPE_WRITE) {
            // Access to a parameter or the return address of the function
            return true;
        }
        offset = Math.abs(offset);
        if (offset > ptr.getRegion().getSize() + ((long) getSafeUnitCnt() * GlobalState.arch.getDefaultPointerSize())) {
            String details = "Stack Out-of-Bound Write";
            String cwe = CWE787;
            Logging.debug("Check OOB for: " + ptr + " at " + address.toString() + "," + context);
            CWEReport report = new CWEReport(cwe, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    /**
     * @hidden
     * @param ptr
     * @param address
     * @param context
     * @param callee
     * @param type
     * @return
     */
    public static boolean checkOutOfBound(AbsVal ptr, AbsEnv env, Address address, Context context, Function callee, int type) {
        assert ptr.getRegion().isHeap() || ptr.getRegion().isLocal();
        if (ptr.getRegion().isHeap()) {
            Heap chunk = (Heap) ptr.getRegion();
            if (env.getLifetime(chunk).isMayLive()) {
                return checkHeapOutOfBound(ptr, address, context, callee, type);
            }
        } else if (ptr.getRegion().isLocal()) {
            return checkStackOutOfBound(ptr, address, context, callee, type);
        }
        return false;
    }

    /**
     * @hidden
     * @param pcode
     * @param inOutEnv
     * @param tmpEnv
     * @param context
     * @param calleeFunc
     * @return
     */
    public static boolean checkExternalCallParameters(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv,
            Context context, Function calleeFunc) {
        boolean passed = true;
        String name = calleeFunc.getName(false);
        if (FreeFunction.getStaticSymbols().contains(name) || name.equals("realloc")) {
            KSet pointers = ExternalFunctionBase.getParamKSet(calleeFunc, 0, inOutEnv);
            if (!pointers.isNormal()) { inOutEnv.markUnresolvedEffect("unresolved_release_target", MemoryEvent.at(pcode, context, "gap")); }
            else {
                for (AbsVal pointer : pointers) {
                    if (pointer.getRegion().isHeap()) {
                        passed &= checkDoubleFree(pointer, inOutEnv, MemoryEvent.at(pcode, context, "release"), calleeFunc, 0);
                    }
                }
            }
        }
        MemoryAccessEffects.Result effects = MemoryAccessEffects.resolve(pcode, inOutEnv, calleeFunc);
        FunctionDefinition signature = VarArgsFunctionBase.getVarArgsSignature(Utils.getAddress(pcode));
        int parameters = signature == null ? calleeFunc.getParameterCount() : signature.getArguments().length;
        List<String> reasons = new ArrayList<>(effects.getGaps());
        if (FunctionModelManager.getExternalFunction(calleeFunc.getName()) == null
                && FunctionModelManager.resolveStd(calleeFunc) == null) {
            reasons.add("unmodeled_call_transfer:" + calleeFunc.getName());
        }
        if (!reasons.isEmpty()) {
            List<KSet> roots = new ArrayList<>();
            if (calleeFunc.getSignatureSource() == null
                    || calleeFunc.getSignatureSource() == ghidra.program.model.symbol.SourceType.DEFAULT
                    || (calleeFunc.hasVarArgs() && signature == null)) {
                roots.add(KSet.getTop());
            }
            for (int i = 0; i < parameters; i++) {
                roots.add(signature == null ? ExternalFunctionBase.getParamKSet(calleeFunc, i, inOutEnv)
                        : ExternalFunctionBase.getVarArgsParamKSet(calleeFunc, signature, i, inOutEnv));
            }
            MemoryEffectScope.Result scope = MemoryEffectScope.resolve(inOutEnv, roots, inOutEnv.getEscapedHeaps());
            for (Heap heap : scope.getHeaps()) {
                for (String gap : reasons) { inOutEnv.markHeapGap(heap, gap, MemoryEvent.at(pcode, context, "gap")); }
            }
            inOutEnv.markEscaped(scope.getHeaps());
            for (String gap : reasons) {
                if (scope.isUnresolved()) { inOutEnv.markUnresolvedEffect(gap, MemoryEvent.at(pcode, context, "gap")); }
                else if (scope.getHeaps().isEmpty()) { inOutEnv.markHeapGap(gap, MemoryEvent.at(pcode, context, "gap")); }
            }
        }
        for (MemoryAccessEffects.Access access : effects.getAccesses()) {
            int i = access.getArgumentIndex();
            KSet pointers = signature == null ? ExternalFunctionBase.getParamKSet(calleeFunc, i, inOutEnv)
                    : ExternalFunctionBase.getVarArgsParamKSet(calleeFunc, signature, i, inOutEnv);
            if (!pointers.isNormal()) {
                if (access.getKind() == MemoryAccessEffects.Kind.WRITE) {
                    inOutEnv.markUnresolvedEffect("unresolved_access_argument", MemoryEvent.at(pcode, context, "gap"));
                } else {
                    inOutEnv.markHeapGap("unresolved_access_argument", MemoryEvent.at(pcode, context, "gap"));
                }
                continue;
            }
            int type = access.getKind() == MemoryAccessEffects.Kind.WRITE ? TYPE_WRITE : TYPE_READ;
            MemoryEvent event = MemoryEvent.at(pcode, context, type == TYPE_WRITE ? "write" : "read");
            passed &= checkNullPointerDereference(pointers, event.getAddress(), context, calleeFunc, TYPE_ARGS, i);
            for (AbsVal pointer : pointers) {
                if (pointer.getRegion().isHeap()) {
                    passed &= checkUseAfterFree(pointer, inOutEnv, event, calleeFunc, i, type, access.isConditional());
                }
                if (pointer.getRegion().isHeap() || pointer.getRegion().isLocal()) {
                    passed &= checkOutOfBound(pointer, inOutEnv, event.getAddress(), context, calleeFunc, type);
                }
            }
        }
        return passed;
    }
}
