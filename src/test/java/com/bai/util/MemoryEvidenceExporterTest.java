// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.util;

import com.bai.env.Context;
import com.bai.env.region.Heap;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class MemoryEvidenceExporterTest {
    @Test
    @SuppressWarnings("unchecked")
    public void keepsFirstAndLaterReleaseContextsDistinct() {
        FlatProgramAPI previous = GlobalState.flatAPI;
        try {
            GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
            FlatProgramAPI api = mock(FlatProgramAPI.class);
            GlobalState.flatAPI = api;
            Function owner = mock(Function.class);
            when(owner.getEntryPoint()).thenReturn(ram.getAddress(0x1000));
            when(owner.getName(false)).thenReturn("owner");
            when(api.getFunctionContaining(any())).thenReturn(owner);
            when(api.toAddr(anyLong())).thenAnswer(call -> ram.getAddress((long) call.getArgument(0)));
            Context first = mock(Context.class);
            Context later = mock(Context.class);
            when(first.getFuncs()).thenReturn(new Function[] {owner});
            when(later.getFuncs()).thenReturn(new Function[] {owner});
            when(first.getCallString()).thenReturn(new long[] {0x1100});
            when(later.getCallString()).thenReturn(new long[] {0x1200});
            Heap chunk = mock(Heap.class);
            when(chunk.getAllocAddress()).thenReturn(ram.getAddress(0x1010));
            when(chunk.getFreeSite()).thenReturn(ram.getAddress(0x1020));
            when(chunk.getFreeContext()).thenReturn(first);
            Function callee = mock(Function.class);
            when(callee.getName(false)).thenReturn("free");

            Map<String, Object> evidence = MemoryEvidenceExporter.doubleFreeEvidence(
                    chunk, ram.getAddress(0x1030), later, callee, 0);
            List<Map<String, Object>> events = (List<Map<String, Object>>) evidence.get("events");
            List<Map<String, Object>> firstFrames = (List<Map<String, Object>>) events.get(0).get("context");
            List<Map<String, Object>> laterFrames = (List<Map<String, Object>>) events.get(1).get("context");
            assertEquals("ram:1100", firstFrames.get(0).get("call_site"));
            assertEquals("ram:1200", laterFrames.get(0).get("call_site"));
            assertEquals("free", ((Map<?, ?>) events.get(1).get("query")).get("callee"));
            assertEquals(List.of(), evidence.get("unknown_reasons"));
            assertEquals(evidence.get("candidate_id"), MemoryEvidenceExporter.doubleFreeEvidence(
                    chunk, ram.getAddress(0x1030), later, callee, 0).get("candidate_id"));
        } finally {
            GlobalState.flatAPI = previous;
        }
    }

    @Test
    public void reportsMissingLocationsWithoutInventingEvidence() {
        Map<String, Object> evidence = MemoryEvidenceExporter.doubleFreeEvidence(
                mock(Heap.class), null, null, null, 0);
        assertEquals(List.of("allocation_site_unknown", "first_release_unknown",
                "later_release_unknown", "later_release_callee_unknown"), evidence.get("unknown_reasons"));
        assertEquals("may", evidence.get("evidence_strength"));
    }
}
