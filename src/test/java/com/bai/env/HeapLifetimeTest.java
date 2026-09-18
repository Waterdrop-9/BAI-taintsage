package com.bai.env;

import com.bai.env.region.Heap;
import ghidra.program.model.address.Address;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class HeapLifetimeTest extends com.bai.util.ARMProgramTestBase {
    @Test public void copiesAndLifetimeOnlyJoinsPreserveBranches() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x1234), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 0, "allocation");
        MemoryEvent release = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 1, "release");
        AbsEnv original = new AbsEnv();
        original.allocate(heap, allocation);
        AbsEnv freed = new AbsEnv(original);
        freed.release(heap, release, true);
        assertTrue(original.getLifetime(heap).isMayLive());
        assertTrue(original.getLifetime(heap).getReleases().isEmpty());
        assertFalse(freed.getLifetime(heap).isMayLive());
        AbsEnv joined = original.join(freed);
        assertNotNull(joined);
        assertTrue(joined.getLifetime(heap).isMayLive());
        assertEquals(1, joined.getLifetime(heap).getReleases().size());
        assertEquals(joined.getLifetime(heap), freed.join(original).getLifetime(heap));
        assertNull(joined.join(joined));
    }
    @Test public void joinsReleaseOriginsAndBoundsThemDeterministically() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x1234), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 0, "allocation");
        AbsEnv base = new AbsEnv();
        base.allocate(heap, allocation);
        AbsEnv left = new AbsEnv(base);
        AbsEnv right = new AbsEnv(base);
        MemoryEvent first = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 1, "release");
        MemoryEvent second = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 2, "release");
        left.release(heap, first, true);
        right.release(heap, second, true);
        assertEquals(java.util.Set.of(first, second), left.join(right).getLifetime(heap).getReleases());
        assertEquals(left.join(right).getLifetime(heap), right.join(left).getLifetime(heap));
        HeapLifetime forward = HeapLifetime.allocated(allocation);
        HeapLifetime reverse = HeapLifetime.allocated(allocation);
        java.util.List<MemoryEvent> events = new java.util.ArrayList<>();
        for (int n = 0; n <= HeapLifetime.RELEASE_LIMIT; n++) {
            events.add(new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, n, "release"));
        }
        for (MemoryEvent event : events) { forward = forward.join(HeapLifetime.allocated(allocation).release(event, true)); }
        java.util.Collections.reverse(events);
        for (MemoryEvent event : events) { reverse = reverse.join(HeapLifetime.allocated(allocation).release(event, true)); }
        assertEquals(forward, reverse);
        assertTrue(forward.getGaps().contains("release_provenance_limit"));
        assertEquals(forward, forward.join(reverse));
    }

    @Test public void reallocationAtSameAbstractSiteDoesNotEraseOlderInstance() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x1234), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 0, "allocation");
        MemoryEvent release = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x1234), null, 1, "release");
        AbsEnv env = new AbsEnv();
        env.allocate(heap, allocation);
        env.release(heap, release, true);
        env.allocate(heap, allocation);
        assertTrue(env.getLifetime(heap).isMayLive());
        assertTrue(env.getLifetime(heap).getReleases().contains(release));
        assertTrue(env.getLifetime(heap).getGaps().contains("allocation_instances_merged"));
        AbsEnv returned = new AbsEnv();
        returned.applyLifetime(env);
        env.release(heap, release, true);
        assertTrue(env.getLifetime(heap).isMayLive());
        assertTrue(env.getLifetime(heap).getReleases().contains(release));
        assertTrue(returned.getLifetime(heap).isMayLive());
    }
    @Test public void unresolvedCoverageParticipatesInJoinAndReturns() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x2000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x2000), null, 0, "allocation");
        AbsEnv before = new AbsEnv();
        before.allocate(heap, allocation);
        AbsEnv after = new AbsEnv(before);
        after.markUnresolvedEffect("unresolved_indirect_call", allocation);
        AbsEnv joined = before.join(after);
        assertNotNull(joined);
        assertTrue(before.getLifetime(heap).getGaps().isEmpty());
        assertTrue(joined.getLifetime(heap).getGaps().contains("unresolved_scope:unresolved_indirect_call"));
        AbsEnv caller = new AbsEnv();
        caller.applyLifetime(joined);
        assertEquals(joined.getLifetime(heap), caller.getLifetime(heap));
    }
}
