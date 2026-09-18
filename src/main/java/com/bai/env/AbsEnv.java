package com.bai.env;

import ghidra.program.model.address.Address;
import com.bai.env.region.Heap;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryAccessException;
import com.bai.env.region.Global;
import com.bai.env.region.Reg;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import org.javimmutable.collections.Holder;
import org.javimmutable.collections.JImmutableMap.Entry;
import org.javimmutable.collections.tree.JImmutableTreeMap;

/**
 * Abstract Environment
 */
public class AbsEnv {

    private JImmutableTreeMap<ALoc, KSet> envMap;
    private Map<Heap, HeapLifetime> lifetimes = Map.of();
    private Set<Heap> escapedHeaps = Set.of();
    private Set<Integer> callInputs = Set.of();
    private KSet callerStack;
    private Set<String> flowGaps = Set.of();

    /**
     * Constructor for an empty abstract environment
     */
    public AbsEnv() {
        envMap = JImmutableTreeMap.of();
    }

    /**
     * Shallow copy constructor from others
     */
    public AbsEnv(AbsEnv other) {
        envMap = other.envMap;
        lifetimes = other.lifetimes;
        escapedHeaps = other.escapedHeaps;
        callInputs = other.callInputs;
        callerStack = other.callerStack;
        flowGaps = other.flowGaps;
    }


    /**
     * Getter for the inner map
     */
    public JImmutableTreeMap<ALoc, KSet> getEnvMap() {
        return envMap;
    }

    /**
     * Join operation for this AbsEnv and the other one
     * @param other The other AbsEnv to be joined into this one
     * @return null if the joined result is the same as the old this one, create a new AbsEnv otherwise.
     */
    public AbsEnv join(AbsEnv other) {
        AbsEnv res = new AbsEnv(this);
        for (Entry<ALoc, KSet> entry : other.envMap) {
            res.set(entry.getKey(), entry.getValue(), false);
        }
        Map<Heap, HeapLifetime> joined = new HashMap<>(lifetimes);
        other.lifetimes.forEach((heap, state) -> joined.merge(heap, state, HeapLifetime::join));
        res.lifetimes = Map.copyOf(joined);
        Set<Heap> escaped = new HashSet<>(escapedHeaps);
        escaped.addAll(other.escapedHeaps);
        res.escapedHeaps = Set.copyOf(escaped);
        Set<Integer> inputs = new HashSet<>(callInputs);
        inputs.addAll(other.callInputs);
        res.callInputs = Set.copyOf(inputs);
        if (callerStack == null) { res.callerStack = other.callerStack; }
        else if (other.callerStack != null) {
            KSet stack = callerStack.join(other.callerStack);
            if (stack != null) { res.callerStack = stack; }
        }
        Set<String> gaps = new HashSet<>(flowGaps);
        gaps.addAll(other.flowGaps);
        res.flowGaps = Set.copyOf(gaps);
        if (inputs.size() > 1) { res.markFlowGap("call_input_correlation_lost"); }
        if (!res.equals(this)) {
            return res;
        }
        // unchanged
        return null;
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof AbsEnv)) { return false; }
        AbsEnv state = (AbsEnv) other;
        return sameValues(state) && callInputs.equals(state.callInputs)
                && java.util.Objects.equals(callerStack, state.callerStack);
    }

    @Override public int hashCode() { return java.util.Objects.hash(envMap, lifetimes, escapedHeaps, callInputs, flowGaps, callerStack); }

    public boolean sameValues(AbsEnv other) {
        return envMap.equals(other.envMap) && lifetimes.equals(other.lifetimes)
                && escapedHeaps.equals(other.escapedHeaps) && flowGaps.equals(other.flowGaps);
    }

    public KSet getCallerStack() { return callerStack; }

    public void setCallerStack(KSet stack) { callerStack = stack; }

    public Set<Integer> getCallInputs() { return callInputs; }

    public void setCallInputs(Set<Integer> inputs) { callInputs = Set.copyOf(inputs); }

    public void markFlowGap(String reason) {
        Set<String> gaps = new HashSet<>(flowGaps);
        gaps.add(reason);
        flowGaps = Set.copyOf(gaps);
    }

    public HeapLifetime getLifetime(Heap heap) {
        HeapLifetime state = lifetimes.getOrDefault(heap, HeapLifetime.unknown());
        for (String gap : flowGaps) { state = state.withGap(gap); }
        return state;
    }

    public Set<Heap> getEscapedHeaps() { return escapedHeaps; }

    public void markEscaped(Set<Heap> heaps) {
        Set<Heap> escaped = new HashSet<>(escapedHeaps);
        escaped.addAll(heaps);
        escapedHeaps = Set.copyOf(escaped);
    }

    public void markUnresolvedEffect(String reason, MemoryEvent event) {
        for (Heap heap : lifetimes.keySet()) { markHeapGap(heap, "unresolved_scope:" + reason); }
        com.bai.util.MemoryEvidenceExporter.recordGap(reason, null, event);
    }

    public void allocate(Heap heap, MemoryEvent event) {
        HeapLifetime previous = lifetimes.get(heap);
        HeapLifetime state = HeapLifetime.allocated(event);
        if (previous != null) {
            state = previous.join(state).withGap("allocation_instances_merged");
            com.bai.util.MemoryEvidenceExporter.recordGap("allocation_instances_merged", heap, event);
        }
        Map<Heap, HeapLifetime> next = new HashMap<>(lifetimes);
        next.put(heap, state);
        lifetimes = Map.copyOf(next);
    }

    public void release(Heap heap, MemoryEvent event, boolean strong) {
        Map<Heap, HeapLifetime> next = new HashMap<>(lifetimes);
        next.put(heap, getLifetime(heap).release(event, strong));
        lifetimes = Map.copyOf(next);
    }

    public void markHeapGap(Heap heap, String reason) {
        Map<Heap, HeapLifetime> next = new HashMap<>(lifetimes);
        next.put(heap, getLifetime(heap).withGap(reason));
        lifetimes = Map.copyOf(next);
    }

    public void markHeapGap(Heap heap, String reason, MemoryEvent event) {
        markHeapGap(heap, reason);
        com.bai.util.MemoryEvidenceExporter.recordGap(reason, heap, event);
    }

    public void markHeapGap(String reason, MemoryEvent event) {
        com.bai.util.MemoryEvidenceExporter.recordGap(reason, null, event);
    }

    public void applyLifetime(AbsEnv other) {
        lifetimes = other.lifetimes;
        escapedHeaps = other.escapedHeaps;
        Set<String> gaps = new HashSet<>(flowGaps);
        gaps.addAll(other.flowGaps);
        flowGaps = Set.copyOf(gaps);
    }

    private void setEmptyALoc(ALoc aLoc, KSet oldKSet, KSet newKSet, boolean isStrongUpdate) {
        assert envMap.findEntry(aLoc).isEmpty();
        if (isStrongUpdate) {
            if (!newKSet.isBot()) {
                envMap = envMap.assign(aLoc, newKSet);
            }
        } else {
            assert (!oldKSet.isBot());
            KSet tmp = oldKSet.join(newKSet);
            if (tmp != null) {
                assert (!tmp.isBot());
                envMap = envMap.assign(aLoc, tmp);
            } else {
                envMap = envMap.assign(aLoc, oldKSet);
            }
        }
    }

    private void setFilledALoc(ALoc aLoc, KSet oldKSet, KSet newKSet, boolean isStrongUpdate) {
        assert envMap.findEntry(aLoc).isFilled();
        if (isStrongUpdate) {
            if (newKSet.isBot()) {
                envMap = envMap.delete(aLoc);
            } else if (!newKSet.equals(oldKSet)) {
                envMap = envMap.assign(aLoc, newKSet);
            }
        } else {
            assert (!oldKSet.isBot());
            KSet tmp = oldKSet.join(newKSet);
            if (tmp != null) {
                assert (!tmp.isBot());
                envMap = envMap.assign(aLoc, tmp);
            }
        }
    }

    private KSet loadFromProgram(ALoc aLoc) {
        assert aLoc.region.isGlobal();
        AbsVal tmp;
        try {
            Address address = GlobalState.flatAPI.toAddr(aLoc.begin);
            byte[] buf = GlobalState.flatAPI.getBytes(address, aLoc.len);
            tmp = AbsVal.bytesToAbsVal(Global.getInstance(), buf);
        } catch (MemoryAccessException | AddressOutOfBoundsException e) {
            tmp = null;
        }
        KSet res = new KSet(aLoc.len * 8);
        if (tmp != null) {
            res = res.insert(tmp);
        }
        return res;
    }

    /**
     * Update a record with a pair of ALoc and KSet inside this AbsEnv
     * @param newALoc ALoc as the key for this record
     * @param newKSet KSet as the value for this record
     * @param isStrongUpdate Flag to indicate strong or weak update
     */
    public void set(ALoc newALoc, KSet newKSet, boolean isStrongUpdate) {
        if (!newKSet.isTop()) {
            assert newALoc.len * 8 == newKSet.getBits();
        }

        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(newALoc);
        if (holder.isEmpty()) {
            // none overlap
            if (!newKSet.isBot()) {
                envMap = envMap.assign(newALoc, newKSet);
            }
        } else {
            Entry<ALoc, KSet> oldEntry = holder.getValue();
            ALoc oldALoc = oldEntry.getKey();
            KSet oldKSet = oldEntry.getValue();

            long newBegin = newALoc.begin;
            long newEnd = newALoc.begin + newALoc.len;
            long oldBegin = oldALoc.begin;
            long oldEnd = oldALoc.begin + oldALoc.len;

            assert oldALoc.region.equals(newALoc.region);
            RegionBase region = newALoc.region;

            if (newALoc.isExactly(oldALoc)) {
                // AAAAAAAA
                // BBBBBBBB
                setFilledALoc(newALoc, oldKSet, newKSet, isStrongUpdate);
            } else if (newALoc.isLeftPartialOverlap(oldALoc)) {
                // ┌─────────────newRemainALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────oldRemainALoc
                // │   │   │
                // ----AAAAAAAA
                // BBBBBBBB----
                final ALoc interALoc = ALoc.getALoc(region, oldBegin, newEnd - oldBegin);
                final ALoc oldRemainALoc = ALoc.getALoc(region, newEnd, oldEnd - newEnd);
                final ALoc newRemainALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);

                final KSet oldInterKSet = oldKSet.truncate(0, newEnd - oldBegin);
                final KSet newInterKSet = newKSet.truncate(oldBegin - newBegin, newEnd - oldBegin);
                final KSet newRemainKSet = newKSet.truncate(0, oldBegin - newBegin);
                final KSet oldRemainKSet = oldKSet.truncate(newEnd - oldBegin, oldEnd - newEnd);

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                envMap = envMap.assign(oldRemainALoc, oldRemainKSet);
                set(newRemainALoc, newRemainKSet, isStrongUpdate);

            } else if (newALoc.isRightPartialOverlap(oldALoc)) {
                // ┌─────────────oldRemainALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────newRemainALoc
                // │   │   │
                // AAAAAAAA----
                // ----BBBBBBBB
                final ALoc interALoc = ALoc.getALoc(region, newBegin, oldEnd - newBegin);
                final ALoc oldRemainALoc = ALoc.getALoc(region, oldBegin, newBegin - oldBegin);
                final ALoc newRemainALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);

                final KSet oldInterKSet = oldKSet.truncate(newBegin - oldBegin, oldEnd - newBegin);
                final KSet newInterKSet = newKSet.truncate(0, oldEnd - newBegin);
                final KSet newRemainKSet = newKSet.truncate(oldEnd - newBegin, newEnd - oldEnd);
                final KSet oldRemainKSet = oldKSet.truncate(0, newBegin - oldBegin);

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                envMap = envMap.assign(oldRemainALoc, oldRemainKSet);
                set(newRemainALoc, newRemainKSet, isStrongUpdate);

            } else if (newALoc.isFullyOverlap(oldALoc)) {
                // ┌─────────────leftALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────rightALoc
                // │   │   │
                // ----AAAA----
                // BBBBBBBBBBBB
                final ALoc interALoc = oldALoc;
                final KSet oldInterKSet = oldKSet;
                final KSet newInterKSet = newKSet.truncate(oldBegin - newBegin, oldEnd - oldBegin);

                setFilledALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                if (newBegin != oldBegin) {
                    ALoc leftALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
                    KSet leftKSet = newKSet.truncate(0, oldBegin - newBegin);
                    set(leftALoc, leftKSet, isStrongUpdate);
                }

                if (newEnd != oldEnd) {
                    ALoc rightALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
                    KSet rightKSet = newKSet.truncate(oldEnd - newBegin, newEnd - oldEnd);
                    set(rightALoc, rightKSet, isStrongUpdate);
                }

            } else if (newALoc.isSubsetOverlap(oldALoc)) {
                // ┌─────────────leftALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────rightALoc
                // │   │   │
                // AAAAAAAAAAAA
                // ----BBBB----
                final ALoc interAloc = newALoc;
                final KSet oldInterKSet = oldKSet.truncate(newBegin - oldBegin, newEnd - newBegin);
                final KSet newInterKSet = newKSet;

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interAloc, oldInterKSet, newInterKSet, isStrongUpdate);
                if (newBegin != oldBegin) {
                    ALoc leftALoc = ALoc.getALoc(region, oldBegin, newBegin - oldBegin);
                    KSet leftKSet = oldKSet.truncate(0, newBegin - oldBegin);
                    envMap = envMap.assign(leftALoc, leftKSet);
                }
                if (newEnd != oldEnd) {
                    ALoc rightALoc = ALoc.getALoc(region, newEnd, oldEnd - newEnd);
                    KSet rightKSet = oldKSet.truncate(newEnd - oldBegin, oldEnd - newEnd);
                    envMap = envMap.assign(rightALoc, rightKSet);
                }
            }

        }
    }

    /**
     * Get KSet for a given ALoc
     * @param aLoc A given ALoc to be queried on
     * @return KSet as the result, may be Bottom, Noraml or Top KSet
     */
    public KSet get(ALoc aLoc) {
        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(aLoc);
        if (holder.isEmpty()) {
            if (aLoc.region.isGlobal()) {
                return loadFromProgram(aLoc);
            }
            return new KSet(aLoc.len * 8);
        }

        Entry<ALoc, KSet> oldEntry = holder.getValue();
        ALoc oldALoc = oldEntry.getKey();
        KSet oldKSet = oldEntry.getValue();

        long newBegin = aLoc.begin;
        long newEnd = aLoc.begin + aLoc.len;
        long oldBegin = oldALoc.begin;
        long oldEnd = oldALoc.begin + oldALoc.len;

        RegionBase region = aLoc.region;
        assert aLoc.region.equals(oldALoc.region);

        assert !oldKSet.isBot();

        if (aLoc.isExactly(oldALoc)) {
            // AAAAAAAA
            // BBBBBBBB
            return oldKSet;
        } else if (aLoc.isLeftPartialOverlap(oldALoc)) {
            // ┌─────────────newRemainALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────oldRemainALoc
            // │   │   │
            // ----AAAAAAAA
            // BBBBBBBB----
            ALoc newRemainALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
            KSet interKSet = oldKSet.truncate(0, newEnd - oldBegin);
            KSet newRemainKSet = get(newRemainALoc);
            return newRemainKSet.concat(interKSet);

        } else if (aLoc.isRightPartialOverlap(oldALoc)) {
            // ┌─────────────oldRemainALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────newRemainALoc
            // │   │   │
            // AAAAAAAA----
            // ----BBBBBBBB
            ALoc newRemainALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
            KSet interKSet = oldKSet.truncate(newBegin - oldBegin, oldEnd - newBegin);
            KSet newRemainKSet = get(newRemainALoc);
            return interKSet.concat(newRemainKSet);
        } else if (aLoc.isFullyOverlap(oldALoc)) {
            // ┌─────────────leftALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────rightALoc
            // │   │   │
            // ----AAAA----
            // BBBBBBBBBBBB
            KSet res = oldKSet;
            if (newBegin != oldBegin) {
                ALoc leftALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
                KSet leftKSet = get(leftALoc);
                res = leftKSet.concat(res);
            }
            if (newEnd != oldEnd) {
                ALoc rightALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
                KSet rightKSet = get(rightALoc);
                res = res.concat(rightKSet);
            }
            return res;
        } else if (aLoc.isSubsetOverlap(oldALoc)) {
            // ┌─────────────leftALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────rightALoc
            // │   │   │
            // AAAAAAAAAAAA
            // ----BBBB----
            return oldKSet.truncate(newBegin - oldBegin, newEnd - newBegin);
        }
        assert false : "Not Reachable";
        return null;
    }

    /**
     * Return the entry inside the inner map which intersects with a given ALoc,
     * return null if no intersection exists in envMap.
     * This is useful for tainting, avoid cutting up ALoc frequently.
     * @param aLoc ALoc to be queried on
     * @return the entry which intersects with the given ALoc, null otherwise.
     */
    public Entry<ALoc, KSet> getOverlapEntry(ALoc aLoc) {
        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(aLoc);
        return holder.getValueOrNull();
    }

    private void writeEntry(StringBuilder sb, ALoc aLoc, KSet kSet) {
        sb.append(aLoc).append(" -> ").append(kSet).append("\n");
    }

    private void writeRegEntry(StringBuilder sb, ALoc aLoc, KSet kSet) {
        Register register = GlobalState.currentProgram.getLanguage()
                .getRegister(GlobalState.flatAPI.getAddressFactory().getRegisterSpace(), aLoc.getBegin(),
                        aLoc.getLen());
        if (register == null) {
            return;
        }
        if (!register.isBaseRegister()) {
            Register parentReg = register.getParentRegister();
            ALoc parentALoc = ALoc.getALoc(Reg.getInstance(), parentReg.getOffset(), parentReg.getNumBytes());
            KSet parentKSet = this.get(parentALoc);
            if (parentKSet.isBot()) {
                writeEntry(sb, aLoc, kSet);
            } else {
                sb.append(parentReg).append(" -> ").append(parentKSet).append("\n");
            }
        } else {
            writeEntry(sb, aLoc, kSet);
        }
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (Entry<ALoc, KSet> entry : envMap) {
            ALoc aLoc = entry.getKey();
            KSet kSet = entry.getValue();
            if (aLoc.getRegion().isReg()) {
                writeRegEntry(stringBuilder, aLoc, kSet);
            } else {
                writeEntry(stringBuilder, aLoc, kSet);
            }

        }
        return stringBuilder.toString();
    }

}
