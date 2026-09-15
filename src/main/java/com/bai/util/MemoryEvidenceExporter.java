// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.util;

import com.bai.env.Context;
import com.bai.env.region.Heap;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Export the stable Memory Evidence Contract without exposing BinAbs abstract state. */
public final class MemoryEvidenceExporter {

    public static final String OUTPUT_ENV = "TAINTSAGE_BINABS_EVIDENCE_PATH";
    public static final String SCHEMA_VERSION = "taintsage.memory_evidence.v1";

    private MemoryEvidenceExporter() {
    }

    public static Map<String, Object> doubleFreeEvidence(
            Heap chunk, Address laterRelease, Context laterContext,
            Function callee, int argumentIndex) {
        Map<String, Object> object = new LinkedHashMap<>();
        object.put("kind", "heap");
        object.put("allocation_site", programPoint(chunk.getAllocAddress()));
        object.put("allocation_context", contextFrames(chunk.getContext()));

        Map<String, Object> first = new LinkedHashMap<>();
        first.put("kind", "release");
        first.put("role", "first_release");
        first.put("program_point", programPoint(chunk.getFreeSite()));
        first.put("context", contextFrames(chunk.getFreeContext()));

        Map<String, Object> query = new LinkedHashMap<>();
        query.put("kind", "call_argument");
        query.put("callee", callee == null ? "" : callee.getName(false));
        query.put("argument_index", argumentIndex);

        Map<String, Object> later = new LinkedHashMap<>();
        later.put("kind", "release");
        later.put("role", "later_release");
        later.put("program_point", programPoint(laterRelease));
        later.put("context", contextFrames(laterContext));
        later.put("query", query);

        List<String> unknown = new ArrayList<>();
        collectMissingPoint("allocation_site", object.get("allocation_site"), unknown);
        collectMissingPoint("first_release", first.get("program_point"), unknown);
        collectMissingPoint("later_release", later.get("program_point"), unknown);
        if (((String) query.get("callee")).isEmpty()) {
            unknown.add("later_release_callee_unknown");
        }

        Map<String, Object> candidate = new LinkedHashMap<>();
        candidate.put("profile", "double_free");
        candidate.put("cwe", "CWE415");
        candidate.put("evidence_strength", "may");
        candidate.put("object", object);
        candidate.put("events", List.of(first, later));
        candidate.put("unknown_reasons", unknown);
        candidate.put("candidate_id", candidateId(candidate));
        return candidate;
    }

    public static void writeConfiguredEvidence() throws IOException {
        String configured = System.getenv(OUTPUT_ENV);
        if (configured == null || configured.isBlank()) {
            return;
        }
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (CWEReport report : Logging.getCWEReports().keySet()) {
            if ("CWE415".equals(report.getCwe()) && report.getStructuredEvidence() != null) {
                candidates.add(report.getStructuredEvidence());
            }
        }
        candidates.sort(Comparator.comparing(item -> String.valueOf(item.get("candidate_id"))));

        Map<String, Object> producer = new LinkedHashMap<>();
        producer.put("name", "BinAbsInspector");
        producer.put("version", "12.0.4-taintsage-release-context");

        Map<String, Object> binary = new LinkedHashMap<>();
        String sha256 = GlobalState.currentProgram.getExecutableSHA256();
        binary.put("sha256", sha256 == null ? "" : sha256.toLowerCase());
        binary.put("program_name", GlobalState.currentProgram.getName());

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("schema_version", SCHEMA_VERSION);
        document.put("producer", producer);
        document.put("binary", binary);
        document.put("analysis_status", "completed");
        document.put("candidates", candidates);
        document.put("diagnostics", List.of());
        writeAtomic(Path.of(configured), document);
    }

    private static Map<String, Object> programPoint(Address address) {
        Map<String, Object> point = new LinkedHashMap<>();
        if (address == null) {
            point.put("function_entry", "");
            point.put("instruction_address", "");
            return point;
        }
        Function function = GlobalState.flatAPI.getFunctionContaining(address);
        point.put(
                "function_entry",
                function == null ? "" : canonicalAddress(function.getEntryPoint()));
        point.put("instruction_address", canonicalAddress(address));
        return point;
    }

    private static List<Map<String, Object>> contextFrames(Context context) {
        List<Map<String, Object>> frames = new ArrayList<>();
        if (context == null) {
            return frames;
        }
        long[] callString = context.getCallString();
        Function[] functions = context.getFuncs();
        for (int i = functions.length - 1; i >= 0; i--) {
            if (functions[i] == null) {
                continue;
            }
            Map<String, Object> frame = new LinkedHashMap<>();
            frame.put("call_site", canonicalAddress(GlobalState.flatAPI.toAddr(callString[i])));
            frame.put("function_entry", canonicalAddress(functions[i].getEntryPoint()));
            frame.put("function_name", functions[i].getName(false));
            frames.add(frame);
        }
        return frames;
    }

    private static String canonicalAddress(Address address) {
        return address.getAddressSpace().getName().toLowerCase()
                + ":" + Long.toUnsignedString(address.getOffset(), 16);
    }

    @SuppressWarnings("unchecked")
    private static void collectMissingPoint(
            String name, Object value, List<String> unknown) {
        if (!(value instanceof Map)) {
            unknown.add(name + "_unknown");
            return;
        }
        Map<String, Object> point = (Map<String, Object>) value;
        if (String.valueOf(point.get("function_entry")).isEmpty()
                || String.valueOf(point.get("instruction_address")).isEmpty()) {
            unknown.add(name + "_unknown");
        }
    }

    private static String candidateId(Map<String, Object> candidate) {
        String object = String.valueOf(candidate.get("object"));
        String events = String.valueOf(candidate.get("events"));
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest((object + "\n" + events).getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder("ma-");
            for (int i = 0; i < 10; i++) {
                result.append(String.format("%02x", bytes[i]));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void writeAtomic(Path output, Map<String, Object> document) throws IOException {
        Path absolute = output.toAbsolutePath();
        if (absolute.getParent() != null) {
            Files.createDirectories(absolute.getParent());
        }
        Path temporary = absolute.resolveSibling(absolute.getFileName() + ".tmp");
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), document);
        try {
            Files.move(
                    temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(temporary, absolute, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
