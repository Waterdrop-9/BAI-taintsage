package com.bai.env;

import java.util.ArrayList;
import java.util.List;

public final class AbsEnvPartitions {
    public static final int DEFAULT_LIMIT = 16;
    private final int limit;
    private final List<AbsEnv> states = new ArrayList<>();
    private boolean summarized;

    public AbsEnvPartitions(int limit) {
        if (limit < 1) { throw new IllegalArgumentException("Partition limit must be positive"); }
        this.limit = limit;
    }

    public boolean add(AbsEnv incoming) {
        if (summarized) {
            AbsEnv joined = states.get(0).join(incoming);
            if (joined == null) { return false; }
            states.set(0, joined);
            return true;
        }
        if (states.contains(incoming)) { return false; }
        if (states.size() < limit) {
            states.add(new AbsEnv(incoming));
        } else {
            AbsEnv joined = joined();
            AbsEnv next = joined.join(incoming);
            states.clear();
            states.add(next == null ? joined : next);
            summarized = true;
        }
        return true;
    }

    public boolean isSummarized() { return summarized; }

    public List<AbsEnv> states() {
        return states.stream().map(AbsEnv::new).collect(java.util.stream.Collectors.toUnmodifiableList());
    }

    public AbsEnv joined() {
        AbsEnv result = new AbsEnv();
        for (AbsEnv state : states) {
            AbsEnv next = result.join(state);
            if (next != null) { result = next; }
        }
        return result;
    }
}
