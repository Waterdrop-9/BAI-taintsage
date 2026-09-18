package com.bai.env;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class ContextInputs {
    private final int limit;
    private final List<AbsEnv> inputs = new ArrayList<>();
    private final List<AbsEnv> exits = new ArrayList<>();

    public ContextInputs(int limit) {
        if (limit < 1) { throw new IllegalArgumentException("Input limit must be positive"); }
        this.limit = limit;
    }

    public int register(AbsEnv caller) {
        for (int i = 0; i < Math.min(inputs.size(), limit); i++) {
            if (inputs.get(i).sameValues(caller)) { return i; }
        }
        AbsEnv snapshot = new AbsEnv(caller);
        snapshot.setCallInputs(Set.of());
        snapshot.setCallerStack(null);
        if (inputs.size() <= limit) {
            inputs.add(snapshot);
            exits.add(null);
            return inputs.size() - 1;
        }
        AbsEnv joined = inputs.get(limit).join(snapshot);
        if (joined != null) { inputs.set(limit, joined); }
        return limit;
    }

    public boolean isOverflow(int input) { return input == limit; }

    public AbsEnv getExit(int input) {
        AbsEnv exit = exits.get(input);
        return exit == null ? null : new AbsEnv(exit);
    }

    public boolean returnFrom(AbsEnv state) {
        if (state.getCallInputs().isEmpty()) { throw new IllegalStateException("Return without a call input"); }
        boolean changed = false;
        AbsEnv result = new AbsEnv(state);
        if (state.getCallInputs().size() > 1) { result.markFlowGap("call_input_correlation_lost"); }
        result.setCallInputs(Set.of());
        result.setCallerStack(null);
        for (int input : state.getCallInputs()) {
            AbsEnv old = exits.get(input);
            AbsEnv joined = old == null ? new AbsEnv(result) : old.join(result);
            if (joined != null) {
                exits.set(input, joined);
                changed = true;
            }
        }
        return changed;
    }

    public KSet getCallerStack(Set<Integer> ids, int bits) {
        KSet result = new KSet(bits);
        for (int id : ids) {
            KSet stack = inputs.get(id).get(ALoc.getSPALoc());
            if (stack.isNormal()) {
                var values = stack.getInnerSet();
                for (AbsVal value : stack) {
                    if (!value.getRegion().isLocal()) { values = values.delete(value); }
                }
                stack = new KSet(values, stack.getBits());
            }
            KSet joined = result.join(stack);
            if (joined != null) { result = joined; }
        }
        return result;
    }
}
