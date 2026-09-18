package com.bai.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.javimmutable.collections.JImmutableMap.Entry;

public final class MemoryEffectScope {
    public static final class Result {
        private final Set<Heap> heaps;
        private final boolean unresolved;

        private Result(Set<Heap> heaps, boolean unresolved) {
            this.heaps = Set.copyOf(heaps);
            this.unresolved = unresolved;
        }

        public Set<Heap> getHeaps() { return heaps; }
        public boolean isUnresolved() { return unresolved; }
    }

    private MemoryEffectScope() { }

    public static Result resolve(AbsEnv env, Collection<KSet> roots, Collection<Heap> escaped) {
        Set<Heap> heaps = new HashSet<>();
        Set<AbsVal> visited = new HashSet<>();
        ArrayDeque<AbsVal> pending = new ArrayDeque<>();
        boolean unresolved = false;
        for (KSet root : roots) {
            if (!root.isNormal()) { unresolved = true; }
            else { for (AbsVal pointer : root) { pending.add(pointer); } }
        }
        for (Heap heap : escaped) { pending.add(AbsVal.getPtr(heap)); }
        int pointerSize = GlobalState.arch.getDefaultPointerSize();
        for (Entry<ALoc, KSet> entry : env.getEnvMap()) {
            if (!entry.getKey().getRegion().isGlobal() || entry.getKey().getLen() < pointerSize) { continue; }
            if (!entry.getValue().isNormal()) { unresolved = true; }
            else { for (AbsVal pointer : entry.getValue()) { pending.add(pointer); } }
        }
        while (!pending.isEmpty()) {
            AbsVal pointer = pending.removeFirst();
            if (!visited.add(pointer)) { continue; }
            if (pointer.isBigVal()) { unresolved = true; continue; }
            if (pointer.getRegion().isHeap()) { heaps.add((Heap) pointer.getRegion()); }
            for (Entry<ALoc, KSet> entry : env.getEnvMap()) {
                ALoc location = entry.getKey();
                if (!location.getRegion().equals(pointer.getRegion()) || location.getLen() < pointerSize) { continue; }
                if (!pointer.getRegion().isHeap()
                        && (pointer.getValue() < location.getBegin()
                        || pointer.getValue() >= location.getBegin() + location.getLen())) { continue; }
                if (!entry.getValue().isNormal()) { unresolved = true; }
                else { for (AbsVal value : entry.getValue()) { pending.add(value); } }
            }
        }
        return new Result(heaps, unresolved);
    }
}
