package com.bai.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.LinkedHashMap;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HexFormat;
import java.security.MessageDigest;

public final class MemorySummaries {
    public static final String INPUT_ENV = "TAINTSAGE_BINABS_SUMMARIES_PATH";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static String inputDigest;
    private static final Map<Address, NativeReleaseSummary> summaries = new HashMap<>();
    private static final Map<Address, Map<String, Object>> accepted = new HashMap<>();
    private static final List<Map<String, Object>> models = new ArrayList<>();

    private MemorySummaries() { }

    public static void reset() {
        inputDigest = null;
        models.clear();
        summaries.clear();
        accepted.clear();
    }

    public static void load(byte[] content, String binarySha256) throws Exception {
        JsonNode document = MAPPER.readTree(content);
        if (document == null || !document.isObject() || document.size() != 2
                || !"taintsage.memory_summaries.v1".equals(document.path("schema_version").asText())
                || !document.path("summaries").isArray()) {
            throw new IllegalArgumentException("Unsupported memory summary document");
        }
        reset();
        inputDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        DecompInterface decompiler = new DecompInterface();
        boolean opened = false;
        var seen = new HashSet<Address>();
        try {
            for (JsonNode model : document.get("summaries")) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("function_entry", model.path("function_entry").asText());
                row.put("status", "rejected");
                row.put("transfer_evaluations", 0);
                row.put("body_fallback_evaluations", 0);
                models.add(row);
                try {
                    if (!binarySha256.equals(model.path("binary_sha256").asText())) {
                        throw new IllegalArgumentException("Summary binary identity mismatch");
                    }
                    Address entry = GlobalState.currentProgram.getAddressFactory().getAddress(model.path("function_entry").asText());
                    if (entry != null && !seen.add(entry)) {
                        summaries.remove(entry);
                        Map<String, Object> previous = accepted.remove(entry);
                        if (previous != null) {
                            previous.put("status", "rejected");
                            previous.put("reason", "Duplicate function summaries");
                        }
                        throw new IllegalArgumentException("Duplicate function summaries");
                    }
                    if (!opened) {
                        opened = decompiler.openProgram(GlobalState.currentProgram);
                        if (!opened) { throw new IllegalArgumentException("Native decompiler could not open program"); }
                    }
                    NativeReleaseSummary summary = NativeReleaseSummary.bind(model, binarySha256, decompiler);
                    summaries.put(summary.function().getEntryPoint(), summary);
                    accepted.put(summary.function().getEntryPoint(), row);
                    row.put("status", "accepted");
                    row.put("reason", "Native body, parameter flow and effect anchor verified");
                } catch (Exception error) {
                    row.put("reason", error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }

    public static void configure(String path) throws Exception {
        if (path == null || path.isBlank()) { return; }
        load(Files.readAllBytes(Path.of(path)), GlobalState.currentProgram.getExecutableSHA256());
    }

    public static boolean tryApply(Function function, PcodeOp call, Context caller, AbsEnv environment) {
        NativeReleaseSummary summary = summaries.get(function.getEntryPoint());
        if (summary == null) { return false; }
        Map<String, Object> row = accepted.get(function.getEntryPoint());
        if (!summary.apply(call, caller, environment)) {
            row.put("body_fallback_evaluations", ((Integer) row.get("body_fallback_evaluations")) + 1);
            return false;
        }
        row.put("transfer_evaluations", ((Integer) row.get("transfer_evaluations")) + 1);
        return true;
    }

    public static Map<String, Object> report() {
        return inputDigest == null ? null : Map.of("input_sha256", inputDigest, "models", models.stream().map(Map::copyOf).toList());
    }
}
