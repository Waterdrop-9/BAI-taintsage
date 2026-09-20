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

    @Test public void mergedAllocationWritesPreserveOlderObjectValues() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x3000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x3000), null, 0, "allocation");
        AbsEnv environment = new AbsEnv();
        ALoc cell = ALoc.getALoc(heap, 0, 4);
        environment.allocate(heap, allocation);
        environment.set(cell, new KSet(32).insert(new AbsVal(11)), true);
        environment.allocate(heap, allocation);
        environment.set(cell, new KSet(32).insert(new AbsVal(22)), true);
        assertEquals(new KSet(32).insert(new AbsVal(11)).insert(new AbsVal(22)), environment.get(cell));
    }

    @Test public void mergedAllocationPartialWritesPreserveOverlap() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x3000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x3000), null, 0, "allocation");
        AbsEnv environment = new AbsEnv();
        environment.allocate(heap, allocation);
        environment.set(ALoc.getALoc(heap, 0, 4), new KSet(32).insert(new AbsVal(0xaaaaaaaaL)), true);
        environment.allocate(heap, allocation);
        environment.set(ALoc.getALoc(heap, 2, 4), new KSet(32).insert(new AbsVal(0xbbbbbbbbL)), true);
        assertEquals(new KSet(16).insert(new AbsVal(0xaaaa)), environment.get(ALoc.getALoc(heap, 0, 2)));
        assertEquals(new KSet(16).insert(new AbsVal(0xaaaa)).insert(new AbsVal(0xbbbb)), environment.get(ALoc.getALoc(heap, 2, 2)));
        assertEquals(new KSet(16).insert(new AbsVal(0xbbbb)), environment.get(ALoc.getALoc(heap, 4, 2)));
    }

    @Test public void singleAllocationWritesStillReplaceOlderValues() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x3000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x3000), null, 0, "allocation");
        AbsEnv environment = new AbsEnv();
        ALoc cell = ALoc.getALoc(heap, 0, 4);
        environment.allocate(heap, allocation);
        environment.set(cell, new KSet(32).insert(new AbsVal(11)), true);
        environment.set(cell, new KSet(32).insert(new AbsVal(22)), true);
        assertEquals(new KSet(32).insert(new AbsVal(22)), environment.get(cell));
    }

    @Test public void stateInstallationDoesNotReplayMergedHeapWrites() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x3000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x3000), null, 0, "allocation");
        AbsEnv environment = new AbsEnv();
        environment.allocate(heap, allocation);
        environment.set(ALoc.getALoc(heap, 0, 4), new KSet(32).insert(new AbsVal(0xaaaaaaaaL)), true);
        environment.allocate(heap, allocation);
        environment.setState(ALoc.getALoc(heap, 2, 4), new KSet(32).insert(new AbsVal(0xbbbbbbbbL)), true);
        assertEquals(new KSet(16).insert(new AbsVal(0xbbbb)), environment.get(ALoc.getALoc(heap, 2, 2)));
        assertEquals(new KSet(16).insert(new AbsVal(0xaaaa)), environment.get(ALoc.getALoc(heap, 0, 2)));
        environment.setState(ALoc.getALoc(heap, 0, 6), new KSet(48).insert(new AbsVal(0xccccccccccccL)), true);
        assertEquals(new KSet(48).insert(new AbsVal(0xccccccccccccL)), environment.get(ALoc.getALoc(heap, 0, 6)));
    }

    @Test public void mergedCardinalitySurvivesCopyJoinAndReturn() {
        Heap heap = Heap.getHeap(com.bai.Utils.getDefaultAddress(0x3000), mock(Context.class));
        MemoryEvent allocation = new MemoryEvent(com.bai.Utils.getDefaultAddress(0x3000), null, 0, "allocation");
        AbsEnv single = new AbsEnv();
        single.allocate(heap, allocation);
        AbsEnv merged = new AbsEnv(single);
        merged.allocate(heap, allocation);
        AbsEnv returned = new AbsEnv();
        returned.applyLifetime(merged);
        for (AbsEnv environment : java.util.List.of(new AbsEnv(merged), single.join(merged), returned)) {
            assertTrue(environment.getLifetime(heap).hasMergedInstances());
            ALoc cell = ALoc.getALoc(heap, 0, 4);
            environment.set(cell, new KSet(32).insert(new AbsVal(11)), true);
            environment.set(cell, new KSet(32).insert(new AbsVal(22)), true);
            assertEquals(new KSet(32).insert(new AbsVal(11)).insert(new AbsVal(22)), environment.get(cell));
        }
        assertFalse(single.getLifetime(heap).hasMergedInstances());
        assertFalse(HeapLifetime.unknown().hasMergedInstances());
    }
}
