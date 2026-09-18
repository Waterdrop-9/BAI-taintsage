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
    public void testGetHeap() {
        Address a1 = Mockito.mock(Address.class);
        Context c1 = Mockito.mock(Context.class);
        Heap h1 = Heap.getHeap(a1, c1);
        Heap h2 = Heap.getHeap(a1, c1);
        assert h1 == h2;

        Address a2 = Mockito.mock(Address.class);
        Context c2 = Mockito.mock(Context.class);
        h1 = Heap.getHeap(a2, c2, 0x100);
        h2 = Heap.getHeap(a2, c2, 0x200);
        assert h1 == h2;
        assert h1.getSize() == 0x200;
    }

}
