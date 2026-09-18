package com.bai.env.region;

import com.bai.env.Context;
import ghidra.program.model.address.Address;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.tuple.Pair;

public class Heap extends RegionBase {
    public static final int DEFAULT_SIZE = 0x6400000;
    private final Address allocAddress;
    private final Context context;
    private static final Map<Pair<Address, Context>, Heap> pool = new HashMap<>();
    private Heap(Address address, Context context) {
        super(TYPE_HEAP, DEFAULT_SIZE);
        this.allocAddress = address;
        this.context = context;
    }
    public Context getContext() { return context; }
    public Address getAllocAddress() { return allocAddress; }
    public static Heap getHeap(Address address, Context context) {
        return pool.computeIfAbsent(Pair.of(address, context), key -> new Heap(address, context));
    }
    public static Heap getHeap(Address address, Context context, long size) {
        Heap heap = getHeap(address, context);
        heap.setSize(Math.min(size, DEFAULT_SIZE));
        return heap;
    }
    public static void resetPool() { pool.clear(); }
    @Override public boolean equals(Object other) {
        if (!(other instanceof Heap)) { return false; }
        Heap heap = (Heap) other;
        return allocAddress.equals(heap.allocAddress) && context == heap.context;
    }
    @Override public int hashCode() { return allocAddress.hashCode() * 31 + System.identityHashCode(context); }
}
