package com.bai.env;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class MemoryEvent {
    private final Address address;
    private final Context context;
    private final int pcodeTime;
    private final String kind;
    private final String functionEntry;
    private final List<Map<String, Object>> contextFrames;

    public MemoryEvent(Address address, Context context, int pcodeTime, String kind) {
        this.address = address;
        this.context = context;
        this.pcodeTime = pcodeTime;
        this.kind = kind;
        Function function = context == null ? null : context.getFunction();
        this.functionEntry = function == null ? "" : canonical(function.getEntryPoint());
        List<Map<String, Object>> frames = new ArrayList<>();
        if (context != null && context.getFuncs() != null && context.getCallString() != null) {
            Function[] functions = context.getFuncs();
            long[] sites = context.getCallString();
            for (int i = functions.length - 1; i >= 0; i--) {
                if (functions[i] != null) {
                    frames.add(Map.of("call_site", canonical(address == null ? null : address.getNewAddress(sites[i])),
                            "function_entry", canonical(functions[i].getEntryPoint()),
                            "function_name", functions[i].getName(false)));
                }
            }
        }
        this.contextFrames = List.copyOf(frames);
    }
    public static MemoryEvent at(PcodeOp operation, Context context, String kind) {
        return new MemoryEvent(operation.getSeqnum().getTarget(), context, operation.getSeqnum().getTime(), kind);
    }
    private static String canonical(Address address) {
        return address == null ? "" : address.getAddressSpace().getName().toLowerCase() + ":" + Long.toHexString(address.getOffset());
    }
    public String stableKey() {
        StringBuilder key = new StringBuilder(functionEntry).append('|').append(address == null ? "" : address.toString(true))
                .append('|').append(pcodeTime).append('|').append(kind);
        for (Map<String, Object> frame : contextFrames) {
            key.append('|').append(frame.get("function_entry")).append('|').append(frame.get("call_site")).append('|').append(frame.get("function_name"));
        }
        return key.toString();
    }
    public Address getAddress() { return address; }
    public Context getContext() { return context; }
    public int getPcodeTime() { return pcodeTime; }
    public String getKind() { return kind; }
    public String getFunctionEntry() { return functionEntry; }
    public List<Map<String, Object>> getContextFrames() { return contextFrames; }
    @Override public boolean equals(Object other) {
        if (!(other instanceof MemoryEvent)) { return false; }
        MemoryEvent event = (MemoryEvent) other;
        return Objects.equals(address, event.address) && pcodeTime == event.pcodeTime
                && kind.equals(event.kind) && functionEntry.equals(event.functionEntry)
                && contextFrames.equals(event.contextFrames);
    }
    @Override public int hashCode() { return Objects.hash(address, pcodeTime, kind, functionEntry, contextFrames); }
}
