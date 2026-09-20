package com.bai.util;

import com.bai.env.HeapLifetime;
import com.bai.env.MemoryEvent;
import com.bai.env.region.Heap;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

public final class MemoryEvidenceExporter {
    public static final String OUTPUT_ENV = "TAINTSAGE_BINABS_EVIDENCE_PATH";
    public static final String SCHEMA_VERSION = "taintsage.memory_evidence.v2";
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final Map<String, Map<String, Object>> CANDIDATES = new TreeMap<>();
    private static final Map<String, Map<String, Object>> GAPS = new TreeMap<>();

    private MemoryEvidenceExporter() { }

    public static void reset() {
        CANDIDATES.clear();
        GAPS.clear();
    }

    public static List<Map<String, Object>> getCandidates() { return List.copyOf(CANDIDATES.values()); }
    public static List<Map<String, Object>> getAnalysisGaps() { return List.copyOf(GAPS.values()); }

    public static void record(String cwe, Heap heap, HeapLifetime lifetime, MemoryEvent terminal,
            Function callee, int argumentIndex, String accessKind) {
        if (!"CWE415".equals(cwe) && !"CWE416".equals(cwe)) {
            throw new IllegalArgumentException("Unsupported memory profile: " + cwe);
        }
        MemoryEvent allocation = lifetime.getAllocation();
        if (allocation == null) {
            recordGap("allocation_event_missing", heap, terminal);
            return;
        }
        Map<String, Object> allocated = event(allocation, "allocation", null);
        Map<String, Object> object = Map.of(
                "object_id", objectId(heap), "kind", "heap", "allocation_event", allocated,
                "allocation_site", allocated.get("program_point"),
                "allocation_context", allocated.get("context"));
        Map<String, Object> query;
        if (callee != null) {
            query = Map.of("kind", "call_argument", "callee", callee.getName(false), "argument_index", argumentIndex);
        } else {
            query = Map.of("kind", "memory_operand", "opcode", "read".equals(accessKind) ? "LOAD" : "STORE", "operand_index", 1);
        }
        boolean doubleFree = "CWE415".equals(cwe);
        Map<String, Object> later = event(terminal, doubleFree ? "later_release" : "use", query);
        for (MemoryEvent release : lifetime.getReleases()) {
            Map<String, Object> first = event(release, "first_release", null);
            TreeSet<String> reasons = new TreeSet<>(lifetime.getGaps());
            if (lifetime.isMayLive()) { reasons.add("lifetime_may_be_live"); }
            if (release.equals(terminal)) { reasons.add("repeated_static_event_order_unknown"); }
            for (MemoryEvent source : List.of(allocation, release, terminal)) {
                if (source.getPcodeTime() < 0) { reasons.add("native_operation_time_unknown"); }
                if (source.getAddress() == null || source.getFunctionEntry().isEmpty()) {
                    recordGap("event_program_point_missing", heap, source);
                    return;
                }
            }
            List<Map<String, Object>> events = List.of(first, later);
            String identity = digest("ma-", Map.of("cwe", cwe, "object_id", object.get("object_id"), "events", events));
            Map<String, Object> candidate = new LinkedHashMap<>();
            candidate.put("candidate_id", identity);
            candidate.put("profile", doubleFree ? "double_free" : "use_after_free");
            candidate.put("cwe", cwe);
            candidate.put("evidence_strength", "may");
            candidate.put("object", object);
            candidate.put("events", events);
            candidate.put("event_order", Map.of("before", first.get("event_id"), "after", later.get("event_id"), "basis", "abstract_execution"));
            candidate.put("unknown_reasons", List.copyOf(reasons));
            Map<String, Object> previous = CANDIDATES.get(identity);
            if (previous != null) {
                int gapCount = ((List<?>) previous.get("unknown_reasons")).size();
                if (gapCount < reasons.size()
                        || (gapCount == reasons.size() && digest("", previous).compareTo(digest("", candidate)) <= 0)) {
                    continue;
                }
            }
            CANDIDATES.put(identity, Collections.unmodifiableMap(candidate));
        }
    }

    public static void recordGap(String reason, Heap heap, MemoryEvent location) {
        Map<String, Object> gap = new LinkedHashMap<>();
        gap.put("reason", reason);
        gap.put("scope", heap == null ? "unresolved" : "object");
        gap.put("object_id", heap == null ? "" : objectId(heap));
        gap.put("program_point", Map.of("function_entry", location.getFunctionEntry(), "instruction_address", canonicalAddress(location.getAddress())));
        gap.put("context", location.getContextFrames());
        Map<String, Object> immutable = Collections.unmodifiableMap(gap);
        GAPS.put(digest("gap-", immutable), immutable);
    }

    private static String objectId(Heap heap) {
        MemoryEvent allocation = new MemoryEvent(heap.getAllocAddress(), heap.getContext(), -1, "allocation");
        return digest("mo-", Map.of("instruction_address", canonicalAddress(allocation.getAddress()),
                "function_entry", allocation.getFunctionEntry(), "context", allocation.getContextFrames()));
    }

    private static Map<String, Object> event(MemoryEvent source, String role, Map<String, Object> query) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("kind", source.getKind());
        value.put("program_point", Map.of("function_entry", source.getFunctionEntry(), "instruction_address", canonicalAddress(source.getAddress())));
        value.put("context", source.getContextFrames());
        value.put("native_pcode_time", source.getPcodeTime());
        if (query != null) { value.put("query", query); }
        value.put("event_id", digest("me-", value));
        value.put("role", role);
        return Collections.unmodifiableMap(value);
    }

    public static void writeConfiguredEvidence(AnalysisOutcome outcome, List<String> entryPoints) throws IOException {
        String configured = System.getenv(OUTPUT_ENV);
        if (configured == null || configured.isBlank()) { return; }
        Map<String, Object> document = new LinkedHashMap<>();
        String sha256 = GlobalState.currentProgram.getExecutableSHA256();
        document.put("schema_version", SCHEMA_VERSION);
        document.put("producer", Map.of("name", "BinAbsInspector", "version", "12.0.4-taintsage-lifetime"));
        document.put("binary", Map.of("sha256", sha256 == null ? "" : sha256.toLowerCase(), "program_name", GlobalState.currentProgram.getName()));
        document.put("analysis_status", outcome.getStatus());
        document.put("entry_points", List.copyOf(entryPoints));
        document.put("candidates", getCandidates());
        document.put("diagnostics", outcome.getDiagnostics());
        document.put("analysis_gaps", getAnalysisGaps());
        var summaries = com.bai.env.funcs.MemorySummaries.report();
        if (summaries != null) { document.put("memory_summaries", summaries); }
        Path output = Path.of(configured).toAbsolutePath();
        if (output.getParent() != null) { Files.createDirectories(output.getParent()); }
        Path temporary = output.resolveSibling(output.getFileName() + ".tmp");
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), document);
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String canonicalAddress(Address address) {
        return address == null ? "" : address.getAddressSpace().getName().toLowerCase()
                + ":" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static String digest(String prefix, Object value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(MAPPER.writeValueAsBytes(value));
            StringBuilder result = new StringBuilder(prefix);
            for (byte item : bytes) { result.append(String.format("%02x", item)); }
            return result.toString();
        } catch (NoSuchAlgorithmException | IOException impossible) {
            throw new IllegalStateException("Cannot identify memory evidence", impossible);
        }
    }
}
