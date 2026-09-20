package com.bai.solver;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.MemoryEvent;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.ContextTransitionTable;
import com.bai.env.Interval;
import com.bai.env.KSet;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.MemorySummaries;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.VarArgsFunctionBase;
import com.bai.env.region.Global;
import com.bai.env.region.Local;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import com.bai.checkers.IntegerOverflowUnderflow;
import com.bai.checkers.MemoryCorruption;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.javimmutable.collections.JImmutableMap;
import org.javimmutable.collections.JImmutableMap.Entry;
import org.javimmutable.collections.JImmutableSet;
import org.javimmutable.collections.tree.JImmutableTreeMap;

public class PcodeVisitor {

    private class Status {

        protected boolean noReturn;
        protected boolean isUpdate;
        protected boolean isExitEmpty;
        protected boolean isFinished;

        public Status(boolean noReturn, boolean isUpdate, boolean isExitEmpty, boolean isFinished) {
            this.noReturn = noReturn;
            this.isUpdate = isUpdate;
            this.isExitEmpty = isExitEmpty;
            this.isFinished = isFinished;
        }

    }

    private Context context;

    private boolean jumpOut = false;

    private boolean switchContext = false;

    private boolean isCBranch = false;

    private boolean isCallInstruction = false;

    private static Map<Address, Map> takenConstraintsMap = new HashMap<>();

    private static Map<Address, Map> fallThroughConstaintsMap = new HashMap<>();

    public PcodeVisitor(Context context) {
        this.context = context;
    }

    private boolean isLastPcodeOfInstruction(PcodeOp pcode) {
        Address address = Utils.getAddress(pcode);
        PcodeOp[] pcodes = GlobalState.flatAPI.getInstructionAt(address).getPcode(true);
        return pcode.getSeqnum().getTime() == (pcodes.length - 1);
    }

    private void processNext(Address address, AbsEnv inOutEnv) {
        CFG cfg = CFG.getCFG(context.getFunction());
        List<Address> successors = cfg.getSuccs(address);
        for (Address successor : successors) {
            context.propagateBefore(successor, inOutEnv);
        }
    }

    public static AddressRange getConstraintBasicBlock(Address address) {
        Function function = GlobalState.flatAPI.getFunctionContaining(address);
        if (function == null) {
            Logging.error("Could not found function containing " + address.toString());
            return null;
        }
        CFG cfg = CFG.getCFG(function);
        Address cur = address;
        boolean stop = false;
        while (true) {
            List<Address> preds = cfg.getPreds(cur);
            if (preds.size() != 1) {
                break;
            }
            List<Address> succs = cfg.getSuccs(preds.get(0));
            if (succs.size() != 1) {
                break;
            }
            PcodeOp[] pcodes = GlobalState.flatAPI.getInstructionAt(preds.get(0)).getPcode(true);
            for (PcodeOp op : pcodes) {
                if (op.getOpcode() == PcodeOp.CBRANCH) {
                    break;
                } else if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    stop = true;
                    break;
                }
                switch (op.getOpcode()) {
                    // Skip constrain solving if encounter unsupported Pcode.
                    case PcodeOp.FLOAT_ABS:
                    case PcodeOp.FLOAT_ADD:
                    case PcodeOp.FLOAT_CEIL:
                    case PcodeOp.FLOAT_DIV:
                    case PcodeOp.FLOAT_EQUAL:
                    case PcodeOp.FLOAT_FLOAT2FLOAT:
                    case PcodeOp.FLOAT_FLOOR:
                    case PcodeOp.FLOAT_INT2FLOAT:
                    case PcodeOp.FLOAT_LESS:
                    case PcodeOp.FLOAT_LESSEQUAL:
                    case PcodeOp.FLOAT_MULT:
                    case PcodeOp.FLOAT_NAN:
                    case PcodeOp.FLOAT_NEG:
                    case PcodeOp.FLOAT_NOTEQUAL:
                    case PcodeOp.FLOAT_ROUND:
                    case PcodeOp.FLOAT_SQRT:
                    case PcodeOp.FLOAT_SUB:
                    case PcodeOp.FLOAT_TRUNC:
                        Logging.debug("Encounter FLOAT Pcode, skip constraint solving.");
                        return null;
                    default: //nothing
                }
            }
            if (stop) {
                break;
            }
            cur = preds.get(0);
        }
        Address start = cur;
        Address end = address;
        return new AddressRangeImpl(start, end);
    }

    /**
     * Solve constraints
     *
     * @param address
     * @param inOutEnv
     * @param context
     * @return the array of ImmutablePair<Address, AbsEnv>, taken pair at index 0, fallthrough pair at index 1;
     */
    @SuppressWarnings("unchecked")
    private ImmutablePair<Address, AbsEnv>[] processConstraints(Address address, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context) {
        PcodeOp[] pcodeOps = GlobalState.flatAPI.getInstructionAt(address).getPcode(true);
        PcodeOp pcode = pcodeOps[pcodeOps.length - 1];
        assert pcode.getOpcode() == PcodeOp.CBRANCH;

        ImmutablePair<Address, AbsEnv>[] res = new ImmutablePair[2];

        Instruction fallThroughInstruction = GlobalState.flatAPI.getInstructionAfter(address);
        if (fallThroughInstruction == null) {
            return res;
        }
        Address fallThroughAddress = fallThroughInstruction.getAddress();
        Varnode dst = pcode.getInput(0);
        assert (dst.getSpace() == GlobalState.flatAPI.getAddressFactory().getDefaultAddressSpace().getSpaceID());
        Address takenAddress = null;
        if (dst.isConstant()) {
            takenAddress = address.getNewAddress(address.getOffset() + dst.getOffset());
        } else if (dst.isAddress()) {
            takenAddress = dst.getAddress();
        }

        Varnode conditionVarnode = pcode.getInput(1);
        if (conditionVarnode.isConstant()) {
            assert conditionVarnode.getSize() == 1;
            if (conditionVarnode.getOffset() == 0) {
                res[1] = ImmutablePair.of(fallThroughAddress, inOutEnv);
            } else {
                res[0] = ImmutablePair.of(takenAddress, inOutEnv);
            }
            return res;
        }

        KSet conditionKSet = getKSet(conditionVarnode, inOutEnv, tmpEnv, pcode);
        if (conditionKSet.isFalse()) {
            res[1] = ImmutablePair.of(fallThroughAddress, inOutEnv);
            return res;
        }
        if (conditionKSet.isTrue()) {
            res[0] = ImmutablePair.of(takenAddress, inOutEnv);
            return res;
        }

        assert conditionKSet.isUnknown();
        ImmutablePair<Address, AbsEnv>[] unsolvedRes = new ImmutablePair[]
                {ImmutablePair.of(takenAddress, inOutEnv),
                        ImmutablePair.of(fallThroughAddress, inOutEnv)};

        Function currentFunction = context.getFunction();
        if (!GlobalState.config.isEnableZ3()
                || currentFunction == null
                || !CFG.getCFG(currentFunction).isInLoop(address)) {
            return unsolvedRes;
        }

        Map<ALoc, Interval> takenBoundMap = null;
        Map<ALoc, Interval> fallThoughBoundMap = null;
        if (!takenConstraintsMap.containsKey(address) || !fallThroughConstaintsMap.containsKey(address)) {
            AddressRange addressRange = getConstraintBasicBlock(address);
            if (addressRange == null) {
                return unsolvedRes;
            }
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(addressRange, context);

            takenBoundMap = constraintSolver.solveBounds(address, true);
            takenConstraintsMap.put(address, takenBoundMap);

            fallThoughBoundMap = constraintSolver.solveBounds(address, false);
            fallThroughConstaintsMap.put(address, fallThoughBoundMap);
        }

        takenBoundMap = takenConstraintsMap.get(address);
        fallThoughBoundMap = fallThroughConstaintsMap.get(address);

        res[0] = ImmutablePair.of(takenAddress, filterAbsEnv(inOutEnv, takenBoundMap));
        res[1] = ImmutablePair.of(fallThroughAddress, filterAbsEnv(inOutEnv, fallThoughBoundMap));
        return res;
    }

    private boolean isAbsValExceedBound(AbsVal absVal, Interval bound, int bits) {
        if (absVal.getRegion().isLocal() || absVal.getRegion().isHeap()) {
            return false;
        }
        if (absVal.getRegion().isGlobal()) {
            if (bound.isBig()) {
                BigInteger bigVal = absVal.toBigInteger(bits, false);
                BigInteger upperBound = AbsVal.toUnsigned(bound.getUpperBig(), bits);
                BigInteger lowerBound = AbsVal.toUnsigned(bound.getLowerBig(), bits);
                return bigVal.compareTo(lowerBound) < 0 || bigVal.compareTo(upperBound) > 0;
            }
            return AbsVal.signExtendToLong(absVal.getValue(), bits) < bound.getLower()
                    || AbsVal.signExtendToLong(absVal.getValue(), bits) > bound.getUpper();
        }
        return false;
    }

    private AbsEnv filterAbsEnv(AbsEnv absEnv, Map<ALoc, Interval> boundMap) {
        if (boundMap == null) {
            return absEnv;
        }
        AbsEnv newAbsEnv = new AbsEnv(absEnv);
        for (JImmutableMap.Entry<ALoc, KSet> entry : absEnv.getEnvMap()) {
            ALoc aLoc = entry.getKey();
            KSet kSet = entry.getValue();
            if (kSet.isTop()) {
                continue;
            }
            Interval bound = boundMap.get(aLoc);
            if (bound != null) {
                JImmutableSet<AbsVal> filteredSet = kSet.getInnerSet();
                for (AbsVal absVal : filteredSet) {
                    if (isAbsValExceedBound(absVal, bound, kSet.getBits())) {
                        filteredSet = filteredSet.delete(absVal);
                    }
                }
                KSet newKSet = new KSet(filteredSet, kSet.getBits(), kSet.getTaints());
                newAbsEnv.setState(aLoc, newKSet, true);
            }
        }
        return newAbsEnv;
    }

    private void processCBranchNext(Address address, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        ImmutablePair<Address, AbsEnv>[] validEnvPairs = processConstraints(address, inOutEnv, tmpEnv, context);
        assert validEnvPairs.length == 2;
        for (int i = 0; i < validEnvPairs.length; i++) {
            ImmutablePair<Address, AbsEnv> pair = validEnvPairs[i];
            if (pair == null) {
                continue;
            }
            Address successorAddress = pair.getLeft();
            context.propagateBefore(successorAddress, pair.getRight());
        }
    }

    private KSet getPCKSet(PcodeOp pcode, AbsEnv tmpEnv) {
        ALoc pcALoc = ALoc.getALoc(
                Reg.getInstance(), GlobalState.arch.getPcIndex(), GlobalState.arch.getDefaultPointerSize());
        KSet pcKSet = tmpEnv.get(pcALoc);
        if (!pcKSet.isNormal()) {
            Address currentAddress = pcode.getSeqnum().getTarget();
            return GlobalState.arch.getPcKSet(currentAddress);
        }
        return pcKSet;
    }

    private KSet getKSet(Varnode src, AbsEnv inOutEnv, AbsEnv tmpEnv, PcodeOp pcode) {
        if (src.isConstant()) {
            return new KSet(src.getSize() * 8)
                    .insert(new AbsVal(Global.getInstance(), src.getOffset()));
        }
        if (src.isRegister() && src.getOffset() == GlobalState.arch.getPcIndex()) {
            return getPCKSet(pcode, tmpEnv);
        }
        ALoc srcALoc = ALoc.getALoc(src);
        if (src.isUnique()) {
            return tmpEnv.get(srcALoc);
        }
        return inOutEnv.get(srcALoc);
    }

    private void setKSet(Varnode dst, KSet srcKSet, AbsEnv inOutEnv, AbsEnv tmpEnv, boolean isStrongUpdate) {
        ALoc dstALoc = ALoc.getALoc(dst);
        if (dst.isUnique() || dstALoc.isPC()) {
            tmpEnv.set(dstALoc, srcKSet, isStrongUpdate);
        } else {
            inOutEnv.set(dstALoc, srcKSet, isStrongUpdate);
        }
    }



    /**
     * Tracking the size of local region, mainly for stack out of bound checking.
     * @param dst
     * @param kSet
     */
    private void updateLocalSize(Varnode dst, KSet kSet) {
        if (!(dst.isRegister() && dst.getOffset() == GlobalState.arch.getSpIndex())) {
            return;
        }
        if (isCallInstruction) {
            // x86 call instruction will push return address on stack,
            // we don't update local size for this case
            return;
        }
        if (!kSet.isNormal()) {
            return;
        }
        for (AbsVal absVal : kSet) {
            if (!absVal.getRegion().isLocal() || absVal.isBigVal()) {
                continue;
            }
            long newSize = Math.abs(absVal.getOffset());
            Local local = (Local) absVal.getRegion();
            if (local.getSize() == Local.DEFAULT_SIZE) {
                if (newSize > 0 && newSize < Local.DEFAULT_SIZE) {
                    local.setSize(newSize);
                    Logging.debug("Update Local size for " + local + " to:" + newSize);
                }
            } else {
                if (newSize > local.getSize() && newSize <= Local.DEFAULT_SIZE) {
                    local.setSize(newSize);
                    Logging.debug("Update Local size for " + local + " to:" + newSize);
                }
            }
        }
    }

    private void defineExternalFunctionSignature(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Function callee) {
        String funcName = callee.getName();
        ExternalFunctionBase externalFunction = FunctionModelManager.getExternalFunction(funcName);
        if (externalFunction == null) {
            return;
        }
        externalFunction.defineDefaultSignature(callee);
        if (externalFunction instanceof VarArgsFunctionBase) {
            ((VarArgsFunctionBase) externalFunction).processVarArgsSignature(pcode, inOutEnv, callee);
        }
    }

    private Status invokeExternal(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Function callee) {
        String funcName = callee.getName();
        ExternalFunctionBase externalFunction = FunctionModelManager.getExternalFunction(funcName);
        if (externalFunction != null) {
            Logging.debug("Invoke external function model: " + funcName);
            externalFunction.invoke(pcode, inOutEnv, tmpEnv, context, callee);
        } else {
            inOutEnv.markHeapGap("unmodeled_call_transfer:" + funcName, MemoryEvent.at(pcode, context, "gap"));
        }
        if (GlobalState.arch.isX86()) {
            // pop return address on stack
            ALoc spALoc = ALoc.getALoc(
                    Reg.getInstance(), GlobalState.arch.getSpIndex(), GlobalState.arch.getDefaultPointerSize());
            KSet spKSet = inOutEnv.get(spALoc);
            KSet adjustedKSet = spKSet.add(
                    new KSet(spALoc.getLen() * 8).insert(new AbsVal(GlobalState.arch.getDefaultPointerSize())));
            inOutEnv.set(spALoc, adjustedKSet, true);
        }
        return new Status(callee.hasNoReturn(), false, false, true);
    }

    private Status invokeStd(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Function callee,
            FunctionModelManager.StdCallModel resolved) {
        resolved.handler().invoke(pcode, inOutEnv, tmpEnv, context, callee);
        inOutEnv.markHeapGap("container_state_not_path_sensitive", MemoryEvent.at(pcode, context, "gap"));
        if (GlobalState.arch.isX86()) {
            // pop return address on stack
            ALoc spALoc = ALoc.getALoc(
                    Reg.getInstance(), GlobalState.arch.getSpIndex(), GlobalState.arch.getDefaultPointerSize());
            KSet spKSet = inOutEnv.get(spALoc);
            KSet adjustedKSet = spKSet.add(
                    new KSet(spALoc.getLen() * 8).insert(new AbsVal(GlobalState.arch.getDefaultPointerSize())));
            inOutEnv.set(spALoc, adjustedKSet, true);
        }
        return new Status(callee.hasNoReturn(), false, false, true);
    }


    private KSet loadPtr(AbsVal ptr, KSet inKSet, AbsEnv absEnv, Varnode dst) {
        ALoc aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), dst.getSize());
        KSet srcKSet = absEnv.get(aLoc);
        KSet outKSet = inKSet.join(srcKSet);
        return (outKSet == null) ? inKSet : outKSet;
    }


    private void storePtr(AbsVal ptr, KSet srcKSet, AbsEnv inOutEnv, AbsEnv tmpEnv, Varnode src, boolean strong) {
        ALoc aLoc;
        if (srcKSet.isTop()) {
            aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), src.getSize());
        } else {
            // NOTE : set the size as srcKSet does not follow pcode document,
            //  but can avoid leading '00' and improve precision.
            aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), srcKSet.getBits() / 8);
        }
        AbsEnv env;
        if (ptr.getRegion().isUnique() || aLoc.isPC()) {
            env = tmpEnv;
        } else {
            env = inOutEnv;
        }
        env.set(aLoc, srcKSet, strong);
    }

    public void visit_COPY(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet srcKSet = getKSet(src, inOutEnv, tmpEnv, pcode);
        setKSet(dst, srcKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, srcKSet);
    }

    public void visit_LOAD(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode addressSpaceId = pcode.getInput(0);
        assert addressSpaceId.isConstant();

        Varnode src = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        Address address = Utils.getAddress(pcode);

        KSet srcPtrKSet = getKSet(src, inOutEnv, tmpEnv, pcode);
        KSet newSrcKSet = new KSet(dst.getSize() * 8);
        if (srcPtrKSet.isTop()) {
            inOutEnv.markHeapGap("unresolved_load_target", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            setKSet(dst, KSet.getTop(), inOutEnv, tmpEnv, true);
            return;
        }
        // CWE476: Null Pointer Dereference
        MemoryCorruption.checkNullPointerDereference(srcPtrKSet, address, context, null, MemoryCorruption.TYPE_READ, 0);
        for (AbsVal ptr : srcPtrKSet) {
            if (ptr.isBigVal()) {
                continue;
            }
            if (ptr.getRegion().isHeap()) {
                // CWE416: Use After Free
                MemoryCorruption.checkUseAfterFree(ptr, inOutEnv, MemoryEvent.at(pcode, context, "read"), null, 0, MemoryCorruption.TYPE_READ, false);
            }
            if (ptr.getRegion().isHeap() || ptr.getRegion().isLocal()) {
                // CWE125: Out-of-bounds Read
                MemoryCorruption.checkOutOfBound(ptr, inOutEnv, address, context, null, MemoryCorruption.TYPE_READ);
            }
            var access = Utils.adjustLocalAbsVal(ptr, context, inOutEnv);
            if (access.unresolved()) {
                inOutEnv.markFlowGap("unresolved_caller_stack");
                inOutEnv.markUnresolvedEffect("unresolved_caller_stack", MemoryEvent.at(pcode, context, "gap"));
                newSrcKSet = KSet.getTop();
                continue;
            }
            List<AbsVal> adjustedPtrs = access.targets();
            if (adjustedPtrs.isEmpty()) {
                // not adjusted
                newSrcKSet = loadPtr(ptr, newSrcKSet, inOutEnv, dst);
            } else {
                // join all AbsVal load from adjustedPtrs
                for (AbsVal adjustedPtr : adjustedPtrs) {
                    newSrcKSet = loadPtr(adjustedPtr, newSrcKSet, inOutEnv, dst);
                }
            }
        }
        setKSet(dst, newSrcKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, newSrcKSet);
    }

    public void visit_STORE(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode addressSpaceId = pcode.getInput(0);
        assert addressSpaceId.isConstant();

        Varnode dst = pcode.getInput(1);
        Varnode src = pcode.getInput(2);

        KSet srcKSet = getKSet(src, inOutEnv, tmpEnv, pcode);
        KSet dstPtrKSet = getKSet(dst, inOutEnv, tmpEnv, pcode);

        if (dstPtrKSet.isTop()) {
            inOutEnv.markUnresolvedEffect("unresolved_store_target", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            return;
        }

        Address address = Utils.getAddress(pcode);
        // CWE476: Null Pointer Dereference
        MemoryCorruption.checkNullPointerDereference(dstPtrKSet, address, context, null, MemoryCorruption.TYPE_WRITE,
                0);

        for (AbsVal ptr : dstPtrKSet) {
            if (ptr.isBigVal()) {
                continue;
            }
            if (ptr.getRegion().isHeap()) {
                // CWE416: Use After Free
                MemoryCorruption.checkUseAfterFree(ptr, inOutEnv, MemoryEvent.at(pcode, context, "write"), null, 0, MemoryCorruption.TYPE_WRITE, false);
            }
            if (ptr.getRegion().isHeap() || ptr.getRegion().isLocal()) {
                // CWE787: Out-of-bounds Write check
                MemoryCorruption.checkOutOfBound(ptr, inOutEnv, address, context, null, MemoryCorruption.TYPE_WRITE);
            }
            // Adjust local AbsVal after check.
            var access = Utils.adjustLocalAbsVal(ptr, context, inOutEnv);
            if (access.unresolved()) {
                inOutEnv.markFlowGap("unresolved_caller_stack");
                inOutEnv.markUnresolvedEffect("unresolved_caller_stack", MemoryEvent.at(pcode, context, "gap"));
                for (var cell : inOutEnv.getEnvMap()) {
                    if (cell.getKey().getRegion().isLocal()) {
                        inOutEnv.set(cell.getKey(), KSet.getTop(), true);
                    }
                }
                continue;
            }
            List<AbsVal> adjustedPtrs = access.targets();
            if (adjustedPtrs.isEmpty()) {
                storePtr(ptr, srcKSet, inOutEnv, tmpEnv, src, dstPtrKSet.isSingleton());
            } else {
                // we still write on adjusted ptr, though it might indicate a stack overflow.
                for (AbsVal adjustedPtr : adjustedPtrs) {
                    storePtr(adjustedPtr, srcKSet, inOutEnv, tmpEnv, src, dstPtrKSet.isSingleton() && adjustedPtrs.size() == 1);
                }
            }
        }
    }

    public void visit_BRANCH(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode target = pcode.getInput(0);
        CFG cfg = CFG.getCFG(context.getFunction());
        Address srcAddress = Utils.getAddress(pcode);
        Address dstAddress = null;
        if (target.isConstant()) {
            Logging.debug("Skip relative offset into the indexed list of p-code operations");
            return;
        }
        if (target.isAddress()) {
            dstAddress = target.getAddress();
        }
        cfg.addEdge(srcAddress, dstAddress);
        cfg.refresh();
    }

    public void visit_CBRANCH(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        if (!isLastPcodeOfInstruction(pcode)) {
            Varnode target = pcode.getInput(0);
            Varnode condition = pcode.getInput(1);
            Address address = target.getAddress();
            if (!address.isLoadedMemoryAddress()) {
                return;
            }
            KSet conditionKSet = getKSet(condition, inOutEnv, tmpEnv, pcode);
            if (!conditionKSet.isFalse()) {
                jumpOut = conditionKSet.isTrue();
                context.propagateBefore(address, inOutEnv);
            }
            return;
        }
        Address currentAddress = Utils.getAddress(pcode);
        Instruction fallThroughInstruction = GlobalState.flatAPI.getInstructionAfter(currentAddress);
        CFG cfg = CFG.getCFG(context.getFunction());
        if (fallThroughInstruction != null) {
            Address fallThoughAddress = fallThroughInstruction.getAddress();
            Varnode dst = pcode.getInput(0);
            assert (dst.getSpace() == GlobalState.flatAPI.getAddressFactory().getDefaultAddressSpace().getSpaceID());
            Address takenAddress = null;
            if (dst.isConstant()) {
                Logging.debug("Skip relative offset into the indexed list of p-code operations");
            } else if (dst.isAddress()) {
                takenAddress = dst.getAddress();
            }
            cfg.addEdge(currentAddress, fallThoughAddress);
            cfg.addEdge(currentAddress, takenAddress);
        }
        cfg.refresh();
        isCBranch = true;
    }

    public void visit_BRANCHIND(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode offset = pcode.getInput(0);
        KSet offsetKSet = getKSet(offset, inOutEnv, tmpEnv, pcode);
        if (offsetKSet.isTop()) {
            return;
        }
        CFG cfg = CFG.getCFG(context.getFunction());
        Address currentAddress = Utils.getAddress(pcode);
        for (AbsVal offsetVal : offsetKSet) {
            if (offsetVal.getRegion().isGlobal() && !offsetVal.isBigVal()) {
                Address targetAddress = currentAddress.getNewAddress(currentAddress.getOffset() + offsetVal.getValue());
                MemoryBlock block = GlobalState.flatAPI.getMemoryBlock(targetAddress);
                if (block != null && block.isExecute()) {
                    cfg.addEdge(currentAddress, targetAddress);
                }
            }
        }
        cfg.refresh();
    }

    public void visit_CALL(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Address targetAddress = pcode.getInput(0).getAddress();
        final Address callSite = Utils.getAddress(pcode);
        Function callee = GlobalState.flatAPI.getFunctionAt(targetAddress);

        if (callee == null) {
            inOutEnv.markUnresolvedEffect("unresolved_direct_call", MemoryEvent.at(pcode, context, "gap"));
            return;
        }
        if (callee.isThunk()) {
            callee = callee.getThunkedFunction(true);
        }

        if (callee.isExternal() || FunctionModelManager.isFunctionAddressMapped(targetAddress)) {
            defineExternalFunctionSignature(pcode, inOutEnv, tmpEnv, callee);
            MemoryCorruption.checkExternalCallParameters(pcode, inOutEnv, tmpEnv, context, callee);
            Status status = invokeExternal(pcode, inOutEnv, tmpEnv, callee);
            if (status.noReturn) {
                jumpOut = true;
            }
            return;
        }

        var stdCall = FunctionModelManager.resolveStd(callee);
        if (stdCall != null) {
            Logging.debug("Calling C++ STL: " + callee.getName(true));
            stdCall.model().defineDefaultSignature(callee);
            MemoryCorruption.checkExternalCallParameters(pcode, inOutEnv, tmpEnv, context, callee);
            Status status = invokeStd(pcode, inOutEnv, tmpEnv, callee, stdCall);
            if (status.noReturn) {
                jumpOut = true;
            }
            return;
        }

        if (MemorySummaries.tryApply(callee, pcode, context, inOutEnv)) { return; }

        Context newContext = Context.getContext(context, callSite, callee);
        Logging.debug("New Context: " + newContext.toString());

        if (callee.hasNoReturn()) {
            newContext.initContext(inOutEnv, false);
            jumpOut = true;
        } else {
            ContextTransitionTable.getInstance().add(callSite, context);
            var invocation = newContext.initContext(inOutEnv, false);
            boolean isUpdated = invocation.updated();
            AbsEnv exit = newContext.getExitValue(invocation);
            if (isUpdated) {
                context.insertToWorklist(callSite);
                switchContext = true;
                if (context.equals(newContext)) {
                    Context.pushActive(context);
                } else {
                    Context.pushPending(context);
                    Context.pushActive(newContext);
                }
            } else if (exit == null) {
                switchContext = true;
                if (context.equals(newContext)) {
                    Context.pushActive(context);
                } else {
                    Context.pushPending(context);
                    Context.pushActive(newContext);
                }
            } else {
                inOutEnv.applyLifetime(exit);
                for (JImmutableMap.Entry<ALoc, KSet> entry : exit.getEnvMap()) {
                    if (GlobalState.config.getPreserveCalleeSavedReg()) {
                        // do not overwrite callee saved register
                        if (GlobalState.arch.isCalleeSavedRegister(entry.getKey())) {
                            continue;
                        }
                    }
                    inOutEnv.setState(entry.getKey(), entry.getValue(), true);
                }
            }
        }
    }

    /**
     * @param pcode
     * @param inOutEnv
     * @param tmpEnv
     */
    public void visit_CALLIND(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode target = pcode.getInput(0);
        KSet targetKSet = getKSet(target, inOutEnv, tmpEnv, pcode);

        if (targetKSet.isTop()) {
            inOutEnv.markUnresolvedEffect("unresolved_indirect_call", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            return;
        }

        Set<Pair<Function, Address>> functionSet = new HashSet<>();
        Address callSite = Utils.getAddress(pcode);
        for (AbsVal targetVal : targetKSet) {
            if (!targetVal.getRegion().isGlobal() || targetVal.isBigVal()) {
                inOutEnv.markUnresolvedEffect("unresolved_indirect_call_target", MemoryEvent.at(pcode, context, "gap"));
                continue;
            }
            Address targetAddress = GlobalState.flatAPI.toAddr(targetVal.getValue());
            MemoryBlock block = GlobalState.flatAPI.getMemoryBlock(targetAddress);
            if (block == null || !targetAddress.isLoadedMemoryAddress()) {
                inOutEnv.markUnresolvedEffect("unresolved_indirect_call_target", MemoryEvent.at(pcode, context, "gap"));
                continue;
            }
            Function targetFunction = GlobalState.flatAPI.getFunctionAt(targetAddress);
            if (targetFunction != null) {
                if (targetFunction.isThunk()) {
                    targetFunction = targetFunction.getThunkedFunction(true);
                }
                Logging.debug("Adding indirect call to " + targetFunction);
                if (targetFunction == null) {
                    inOutEnv.markUnresolvedEffect("unresolved_indirect_call_target", MemoryEvent.at(pcode, context, "gap"));
                    continue;
                }
                functionSet.add(Pair.of(targetFunction, targetAddress));
            } else {
                inOutEnv.markUnresolvedEffect("unresolved_indirect_call_target", MemoryEvent.at(pcode, context, "gap"));
            }
        }

        if (functionSet.isEmpty()) {
            inOutEnv.markUnresolvedEffect("unresolved_indirect_call", com.bai.env.MemoryEvent.at(pcode, context, "gap"));
            return;
        }

        boolean noReturn = true;
        boolean isTotalUpdated = false;
        boolean isExitEmpty = false;
        boolean isFinished = true;
        boolean isSingleton = (functionSet.size()) == 1;

        AbsEnv resEnv = new AbsEnv();
        Set<Context> targets = new HashSet<>();
        Context pending = context;

        for (Pair<Function, Address> pair : functionSet) {
            Function callee = pair.getLeft();
            Address targetAddress = pair.getRight();
            AbsEnv targetEnv = new AbsEnv(inOutEnv);
            AbsEnv targetTmp = new AbsEnv(tmpEnv);
            Status status;
            var stdCall = FunctionModelManager.resolveStd(callee);
            if (callee.isExternal() || FunctionModelManager.isFunctionAddressMapped(targetAddress)) {
                defineExternalFunctionSignature(pcode, targetEnv, targetTmp, callee);
                // CWE119, CWE416, CWE416, CWE476
                MemoryCorruption.checkExternalCallParameters(pcode, targetEnv, targetTmp, context, callee);
                status = invokeExternal(pcode, targetEnv, targetTmp, callee);
                if (status == null) {
                    continue;
                }
                if (!status.noReturn) {
                    AbsEnv joinedTarget = resEnv.join(targetEnv);
                    if (joinedTarget != null) { resEnv = joinedTarget; }
                }
                noReturn &= status.noReturn;
                isExitEmpty |= status.isExitEmpty;
                isFinished = isFinished & status.isFinished;
            } else if (stdCall != null) {
                stdCall.model().defineDefaultSignature(callee);
                // CWE119, CWE416, CWE416, CWE476
                MemoryCorruption.checkExternalCallParameters(pcode, targetEnv, targetTmp, context, callee);
                status = invokeStd(pcode, targetEnv, targetTmp, callee, stdCall);
                if (!status.noReturn) {
                    AbsEnv joinedTarget = resEnv.join(targetEnv);
                    if (joinedTarget != null) { resEnv = joinedTarget; }
                }
                noReturn &= status.noReturn;
                isExitEmpty |= status.isExitEmpty;
                isFinished = isFinished & status.isFinished;
            } else if (MemorySummaries.tryApply(callee, pcode, context, targetEnv)) {
                noReturn = false;
                AbsEnv joinedTarget = resEnv.join(targetEnv);
                if (joinedTarget != null) { resEnv = joinedTarget; }
            } else {
                Context newContext = Context.getContext(context, callSite, callee);
                if (callee.hasNoReturn()) {
                    newContext.initContext(inOutEnv, false);
                    Context.pushActive(newContext);
                    isFinished &= true;
                    if (isSingleton) {
                        jumpOut = true;
                        return;
                    }
                } else {
                    noReturn &= false;
                    ContextTransitionTable.getInstance().add(callSite, context);
                    var invocation = newContext.initContext(inOutEnv, false);
                    boolean isUpdated = invocation.updated();
                    AbsEnv exit = newContext.getExitValue(invocation);
                    if (isUpdated) {
                        targets.add(newContext);
                        isFinished &= false;
                        isTotalUpdated |= true;
                    } else if (exit == null) {
                        targets.add(newContext);
                        isFinished &= false;
                        isExitEmpty |= true;
                    } else {
                        AbsEnv tmp = resEnv.join(new AbsEnv(exit));
                        if (tmp != null) {
                            resEnv = tmp;
                        }
                    }
                }
            }
        }

        if (noReturn) {
            jumpOut = true;
            return;
        }
        if (isExitEmpty) {
            switchContext = true;
            for (Context context : targets) {
                Context.pushActive(context);
            }
            Context.pushPending(pending);
            return;
        }

        if (isTotalUpdated) {
            context.insertToWorklist(callSite);
            switchContext = true;
            for (Context context : targets) {
                Context.pushActive(context);
            }
            Context.pushPending(pending);
            return;
        }

        if (isFinished) {
            inOutEnv.applyLifetime(resEnv);
            for (JImmutableTreeMap.Entry<ALoc, KSet> entry : resEnv.getEnvMap()) {
                if (GlobalState.config.getPreserveCalleeSavedReg()) {
                    // do not overwrite callee saved register
                    if (GlobalState.arch.isCalleeSavedRegister(entry.getKey())) {
                        continue;
                    }
                }
                inOutEnv.setState(entry.getKey(), entry.getValue(), true);
            }
        }
    }

    public void visit_RETURN(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Function function = context.getFunction();
        if (function.hasNoReturn()) {
            return;
        }

        for (Entry<ALoc, KSet> entry : inOutEnv.getEnvMap()) {
            ALoc aLoc = entry.getKey();
            if (aLoc.isSP()) {
                if (GlobalState.arch.isX86()) {
                    KSet spKSet = inOutEnv.get(aLoc);
                    if (spKSet.isNormal()) {
                        KSet adjusted = new KSet(spKSet.getBits(), spKSet.getTaints());
                        for (AbsVal pointer : spKSet) {
                            var access = Utils.adjustLocalAbsVal(pointer, context, inOutEnv);
                            if (access.unresolved()) {
                                inOutEnv.markFlowGap("unresolved_caller_stack");
                                adjusted = KSet.getTop(spKSet.getTaints());
                                break;
                            }
                            if (access.targets().isEmpty()) { adjusted = adjusted.insert(pointer); }
                            else {
                                for (AbsVal target : access.targets()) { adjusted = adjusted.insert(target); }
                            }
                        }
                        inOutEnv.set(aLoc, adjusted, true);
                    }
                } else {
                    inOutEnv.set(aLoc, KSet.getBot(aLoc.getLen() * 8), true);
                }
            } else if (aLoc.getRegion().isLocal()) {
                Function localFunction = ((Local) aLoc.getRegion()).getFunction();
                Function currentFunction = context.getFunction();
                if (localFunction == currentFunction) {
                    inOutEnv.set(aLoc, KSet.getBot(aLoc.getLen() * 8), true);
                }
            }
        }

        if (!context.returnFrom(inOutEnv)) { return; }
        long[] callString = context.getCallString();
        Function[] callStringFunctions = context.getFuncs();
        Address lastCallSite = GlobalState.flatAPI.toAddr(callString[GlobalState.config.getCallStringK() - 1]);
        Function lastFunction = callStringFunctions[GlobalState.config.getCallStringK() - 1];
        if (lastFunction == null) {
            return;
        }
        long[] prevCallString = context.popLast();
        Set<long[]> callStringSet = ContextTransitionTable.getInstance().get(lastCallSite, prevCallString);
        if (callStringSet == null) {
            return;
        }
        for (long[] cs : callStringSet) {
            Context callerCtx = Context.getContext(lastFunction, cs);
            if (callerCtx != null) {
                callerCtx.insertToWorklist(lastCallSite);
                if (!Context.isWait(callerCtx)) {
                    Context.pushActive(callerCtx);
                }
            }
        }
    }

    public void visit_INT_EQUAL(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_equal(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_NOTEQUAL(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = (op1KSet.int_equal(op2KSet)).bool_not();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_LESS(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_less(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_SLESS(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_sless(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_LESSEQUAL(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op2KSet.int_less(op1KSet).bool_not();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_SLESSEQUAL(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op2KSet.int_sless(op1KSet).bool_not();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_ZEXT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_zext(dst.getSize() * 8);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_SEXT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_sext(dst.getSize() * 8);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_ADD(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.add(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
        // CWE190: Integer Overflow
        IntegerOverflowUnderflow.checkTaint(op1KSet, op2KSet, pcode, true);
    }

    public void visit_INT_SUB(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.sub(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_CARRY(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_carry(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_SCARRY(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_scarry(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_SBORROW(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_sborrow(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_INT_2COMP(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_2comp();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_NEGATE(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_negate();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_XOR(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_xor(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_AND(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_and(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_OR(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.int_or(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_LEFT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.lshift(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
        // CWE190: Integer Overflow
        IntegerOverflowUnderflow.checkTaint(op1KSet, op2KSet, pcode, true);
    }

    public void visit_INT_RIGHT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.rshift(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_SRIGHT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.srshift(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_MULT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.mult(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
        // CWE190: Integer Overflow
        IntegerOverflowUnderflow.checkTaint(op1KSet, op2KSet, pcode, true);
    }

    public void visit_INT_DIV(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.div(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_REM(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.rem(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_SDIV(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.sdiv(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_INT_SREM(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.srem(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_BOOL_NEGATE(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();
        assert op1.getSize() == dst.getSize();
        assert op1.getSize() == 1;

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.bool_not();
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_BOOL_XOR(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.bool_xor(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_BOOL_AND(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.bool_and(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_BOOL_OR(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet op1KSet = getKSet(op1, inOutEnv, tmpEnv, pcode);
        KSet op2KSet = getKSet(op2, inOutEnv, tmpEnv, pcode);
        KSet resKSet = op1KSet.bool_or(op2KSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
    }

    public void visit_PIECE(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode mostSignificantOp = pcode.getInput(0); // most significant part
        Varnode leastSignificantOp = pcode.getInput(1); // least significant part
        Varnode dst = pcode.getOutput();

        KSet mostSignificantKSet = getKSet(mostSignificantOp, inOutEnv, tmpEnv, pcode);
        KSet leastSignificantKSet = getKSet(leastSignificantOp, inOutEnv, tmpEnv, pcode);
        KSet resKSet = mostSignificantKSet.piece(leastSignificantKSet);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_SUBPIECE(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode srcOp = pcode.getInput(0);
        Varnode bytesOp = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        KSet srcKSet = getKSet(srcOp, inOutEnv, tmpEnv, pcode);
        KSet bytesKSet = getKSet(bytesOp, inOutEnv, tmpEnv, pcode);
        KSet resKSet = srcKSet.subPiece(bytesKSet, dst.getSize() * 8);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit_POPCOUNT(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        Varnode op = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        KSet opKSet = getKSet(op, inOutEnv, tmpEnv, pcode);
        KSet resKSet = opKSet.count_bits(dst.getSize() * 8);
        setKSet(dst, resKSet, inOutEnv, tmpEnv, true);
        updateLocalSize(dst, resKSet);
    }

    public void visit(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv) {
        switch (pcode.getOpcode()) {
            case PcodeOp.COPY:
                visit_COPY(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.LOAD:
                visit_LOAD(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.STORE:
                visit_STORE(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BRANCH:
                visit_BRANCH(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.CBRANCH:
                visit_CBRANCH(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BRANCHIND:
                visit_BRANCHIND(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.CALL:
                visit_CALL(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.CALLIND:
                visit_CALLIND(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.RETURN:
                visit_RETURN(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_EQUAL:
                visit_INT_EQUAL(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_NOTEQUAL:
                visit_INT_NOTEQUAL(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_LESS:
                visit_INT_LESS(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SLESS:
                visit_INT_SLESS(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_LESSEQUAL:
                visit_INT_LESSEQUAL(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SLESSEQUAL:
                visit_INT_SLESSEQUAL(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_ZEXT:
                visit_INT_ZEXT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SEXT:
                visit_INT_SEXT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_ADD:
                visit_INT_ADD(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SUB:
                visit_INT_SUB(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_CARRY:
                visit_INT_CARRY(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SCARRY:
                visit_INT_SCARRY(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SBORROW:
                visit_INT_SBORROW(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_2COMP:
                visit_INT_2COMP(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_NEGATE:
                visit_INT_NEGATE(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_XOR:
                visit_INT_XOR(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_AND:
                visit_INT_AND(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_OR:
                visit_INT_OR(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_LEFT:
                visit_INT_LEFT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_RIGHT:
                visit_INT_RIGHT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SRIGHT:
                visit_INT_SRIGHT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_MULT:
                visit_INT_MULT(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_DIV:
                visit_INT_DIV(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_REM:
                visit_INT_REM(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SDIV:
                visit_INT_SDIV(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.INT_SREM:
                visit_INT_SREM(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BOOL_NEGATE:
                visit_BOOL_NEGATE(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BOOL_XOR:
                visit_BOOL_XOR(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BOOL_AND:
                visit_BOOL_AND(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.BOOL_OR:
                visit_BOOL_OR(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.PIECE:
                visit_PIECE(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.SUBPIECE:
                visit_SUBPIECE(pcode, inOutEnv, tmpEnv);
                break;
            case PcodeOp.POPCOUNT:
                visit_POPCOUNT(pcode, inOutEnv, tmpEnv);
                break;
            default:
                Logging.debug("Skipping unsupported PCode: "
                        + pcode + " @ " + Utils.getAddress(pcode));
        }
    }

    public boolean visit(Address address, AbsEnv inEnv) {
        Function func = GlobalState.flatAPI.getFunctionContaining(address);
        Instruction instruction = GlobalState.flatAPI.getInstructionAt(address);
        if (instruction == null) {
            return false;
        }
        String funcName = func == null ? "***" : func.toString();
        Logging.debug("Visit Inst: " + instruction
                + " @ " + Integer.toHexString((int) address.getOffset()) + " in " + funcName);
        AbsEnv outEnv = new AbsEnv(inEnv);
        AbsEnv tmpEnv = new AbsEnv();

        PcodeOp[] pcodes = instruction.getPcode(true);
        isCallInstruction = Arrays.stream(pcodes).anyMatch(pcodeOp -> pcodeOp.getOpcode() == PcodeOp.CALL);
        if (pcodes.length == 0) {
            processNext(address, inEnv);
        }
        for (PcodeOp pcode : pcodes) {
            visit(pcode, outEnv, tmpEnv);
            if (jumpOut) {
                break;
            }
            if (switchContext) {
                return true;
            }
        }
        if (!jumpOut) {
            if (isCBranch) {
                processCBranchNext(address, outEnv, tmpEnv);
                isCBranch = false;
            } else {
                processNext(address, outEnv);
            }
        }
        jumpOut = false;
        return false;
    }
}
