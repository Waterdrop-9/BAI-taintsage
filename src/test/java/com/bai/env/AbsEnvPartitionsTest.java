package com.bai.env;

import com.bai.Utils;
import com.bai.env.region.Global;
import com.bai.env.region.Reg;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class AbsEnvPartitionsTest {
    private ALoc counter;

    @Before public void setup() {
        com.bai.util.GlobalState.config = new com.bai.util.Config();
        Utils.mockArchitecture(true);
        counter = ALoc.getALoc(Reg.getInstance(), 16, 4);
    }

    @Test public void preservesWholeEnvironmentsWithoutJoiningDifferentCounterValues() {
        AbsEnvPartitions states = new AbsEnvPartitions(2);
        AbsEnv zero = new AbsEnv();
        zero.set(counter, new KSet(32).insert(new AbsVal(Global.getInstance(), 0)), true);
        AbsEnv one = new AbsEnv();
        one.set(counter, new KSet(32).insert(new AbsVal(Global.getInstance(), 1)), true);
        assertTrue(states.add(zero));
        assertTrue(states.add(one));
        assertFalse(states.add(new AbsEnv(zero)));
        assertEquals(2, states.states().size());
        assertEquals(2, states.joined().get(counter).getInnerSet().size());
        for (AbsEnv state : states.states()) {
            assertEquals(1, state.get(counter).getInnerSet().size());
        }
        zero.set(counter, KSet.getTop(32), true);
        assertFalse(states.joined().get(counter).isTop());
    }
    @Test public void saturationIsIrreversibleAndRetainsAllCounterValues() {
        AbsEnvPartitions states = new AbsEnvPartitions(2);
        for (long value = 0; value < 3; value++) {
            AbsEnv state = new AbsEnv();
            state.set(counter, new KSet(32).insert(new AbsVal(value)), true);
            assertTrue(states.add(state));
        }
        assertTrue(states.isSummarized());
        assertEquals(1, states.states().size());
        assertEquals(3, states.joined().get(counter).getInnerSet().size());
        AbsEnv seen = new AbsEnv();
        seen.set(counter, new KSet(32).insert(new AbsVal(1)), true);
        assertFalse(states.add(seen));
        assertTrue(states.isSummarized());
        assertEquals(1, states.states().size());
        states.states().get(0).set(counter, KSet.getTop(32), true);
        assertFalse(states.joined().get(counter).isTop());
    }
    @Test public void equalScalarMapsDoNotEraseLifetimeOrEscapeAlternatives() {
        var ram = new ghidra.program.model.address.GenericAddressSpace("ram", 64,
                ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
        var heap = com.bai.env.region.Heap.getHeap(ram.getAddress(0x1000), null);
        MemoryEvent allocated = new MemoryEvent(ram.getAddress(0x1000), null, 0, "allocation");
        MemoryEvent released = new MemoryEvent(ram.getAddress(0x1001), null, 0, "release");
        AbsEnv live = new AbsEnv();
        live.allocate(heap, allocated);
        AbsEnv freed = new AbsEnv(live);
        freed.release(heap, released, true);
        AbsEnv escaped = new AbsEnv(live);
        escaped.markEscaped(java.util.Set.of(heap));
        AbsEnvPartitions states = new AbsEnvPartitions(3);
        assertTrue(states.add(live));
        assertTrue(states.add(freed));
        assertTrue(states.add(escaped));
        assertFalse(states.add(new AbsEnv(live)));
        assertFalse(states.add(new AbsEnv(freed)));
        assertFalse(states.add(new AbsEnv(escaped)));
        assertEquals(3, states.states().size());
        assertEquals(1, states.states().stream().filter(state -> !state.getLifetime(heap).isMayLive()).count());
        assertEquals(1, states.states().stream().filter(state -> state.getEscapedHeaps().contains(heap)).count());
        live.release(heap, released, true);
        escaped.release(heap, released, true);
        assertEquals(1, states.states().stream().filter(state -> !state.getLifetime(heap).isMayLive()).count());
        assertTrue(states.joined().getLifetime(heap).isMayLive());
        assertEquals(java.util.Set.of(released), states.joined().getLifetime(heap).getReleases());
        assertEquals(java.util.Set.of(heap), states.joined().getEscapedHeaps());
    }
}
