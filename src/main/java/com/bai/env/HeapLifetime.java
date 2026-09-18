package com.bai.env;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public final class HeapLifetime {
    public static final int RELEASE_LIMIT = 32;
    private final MemoryEvent allocation;
    private final boolean mayLive;
    private final Set<MemoryEvent> releases;
    private final Set<String> gaps;

    private HeapLifetime(MemoryEvent allocation, boolean mayLive, Set<MemoryEvent> releases, Set<String> gaps) {
        this.allocation = allocation;
        this.mayLive = mayLive;
        Set<String> allGaps = new HashSet<>(gaps);
        if (releases.size() > RELEASE_LIMIT) { allGaps.add("release_provenance_limit"); }
        this.releases = Set.copyOf(releases.stream().sorted(java.util.Comparator.comparing(MemoryEvent::stableKey))
                .limit(RELEASE_LIMIT).collect(java.util.stream.Collectors.toList()));
        this.gaps = Set.copyOf(allGaps);
    }
    public static HeapLifetime allocated(MemoryEvent event) { return new HeapLifetime(event, true, Set.of(), Set.of()); }
    public static HeapLifetime unknown() { return new HeapLifetime(null, true, Set.of(), Set.of("allocation_state_missing")); }
    public MemoryEvent getAllocation() { return allocation; }
    public boolean isMayLive() { return mayLive; }
    public Set<MemoryEvent> getReleases() { return releases; }
    public Set<String> getGaps() { return gaps; }
    public HeapLifetime withGap(String gap) {
        Set<String> next = new HashSet<>(gaps);
        next.add(gap);
        return new HeapLifetime(allocation, mayLive, releases, next);
    }
    public HeapLifetime release(MemoryEvent event, boolean strong) {
        Set<MemoryEvent> next = new HashSet<>(releases);
        if (mayLive) { next.add(event); }
        return new HeapLifetime(allocation, (!strong || gaps.contains("allocation_instances_merged")) && mayLive, next, gaps);
    }
    public HeapLifetime join(HeapLifetime other) {
        Set<MemoryEvent> events = new HashSet<>(releases);
        events.addAll(other.releases);
        Set<String> reasons = new HashSet<>(gaps);
        reasons.addAll(other.gaps);
        MemoryEvent source = allocation == null ? other.allocation : allocation;
        if (allocation != null && other.allocation != null && !allocation.equals(other.allocation)) {
            source = null;
            reasons.add("allocation_provenance_merged");
        }
        if (reasons.contains("allocation_provenance_merged")) { source = null; }
        return new HeapLifetime(source, mayLive || other.mayLive, events, reasons);
    }
    @Override public boolean equals(Object other) {
        if (!(other instanceof HeapLifetime)) { return false; }
        HeapLifetime state = (HeapLifetime) other;
        return mayLive == state.mayLive && Objects.equals(allocation, state.allocation)
                && releases.equals(state.releases) && gaps.equals(state.gaps);
    }
    @Override public int hashCode() { return Objects.hash(allocation, mayLive, releases, gaps); }
}
