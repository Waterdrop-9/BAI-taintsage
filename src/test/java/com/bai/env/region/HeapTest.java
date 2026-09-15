// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.env.region;


import com.bai.env.Context;
import com.bai.util.Architecture;
import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;

public class HeapTest {
    private Architecture previousArchitecture;

    @Before
    public void setUpArchitecture() {
        previousArchitecture = GlobalState.arch;
        GlobalState.arch = Mockito.mock(Architecture.class);
        Mockito.when(GlobalState.arch.getWordBits()).thenReturn(64);
        Heap.resetPool();
    }

    @After
    public void restoreArchitecture() {
        Heap.resetPool();
        GlobalState.arch = previousArchitecture;
    }

    @Test
    public void preservesFirstReleaseContextAcrossLaterReleases() {
        Heap allocated = Heap.getHeap(Mockito.mock(Address.class), Mockito.mock(Context.class), true);
        Address firstSite = Mockito.mock(Address.class);
        Context firstContext = Mockito.mock(Context.class);
        Heap freed = allocated.toInvalid(firstSite, firstContext);
        Heap releasedAgain = freed.toInvalid(Mockito.mock(Address.class), Mockito.mock(Context.class));
        org.junit.Assert.assertSame(freed, releasedAgain);
        org.junit.Assert.assertSame(firstSite, releasedAgain.getFreeSite());
        org.junit.Assert.assertSame(firstContext, releasedAgain.getFreeContext());
    }

    @Test
    public void legacyReleaseHasNoInventedContext() {
        Heap allocated = Heap.getHeap(Mockito.mock(Address.class), Mockito.mock(Context.class), true);
        org.junit.Assert.assertNull(allocated.toInvalid(Mockito.mock(Address.class)).getFreeContext());
    }

    @Test
    public void testGetHeap() {
        Address a1 = Mockito.mock(Address.class);
        Context c1 = Mockito.mock(Context.class);
        Heap h1 = Heap.getHeap(a1, c1, true);
        Heap h2 = Heap.getHeap(a1, c1, true);
        assert h1 == h2;

        Address a2 = Mockito.mock(Address.class);
        Context c2 = Mockito.mock(Context.class);
        h1 = Heap.getHeap(a2, c2, 0x100, true);
        h2 = Heap.getHeap(a2, c2, 0x200, true);
        assert h1 == h2;
        assert h1.getSize() == 0x200;
    }

    @Test
    public void testToInvalid() {
        Address a1 = Mockito.mock(Address.class);
        Context c1 = Mockito.mock(Context.class);
        Heap h1 = Heap.getHeap(a1, c1, true);
        Heap h2 = h1.toInvalid(a1);
        Heap h3 = Heap.getHeap(a1, c1, true);
        assert h1.equals(h3);
        assert !h3.equals(h2);
    }
}
