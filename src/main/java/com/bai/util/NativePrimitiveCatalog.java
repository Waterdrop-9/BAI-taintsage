package com.bai.util;

import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.externalfuncs.CallocFunction;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.MallocFunction;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class NativePrimitiveCatalog {
    public static final String OUTPUT_ENV = "TAINTSAGE_BINABS_PRIMITIVES_PATH";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private NativePrimitiveCatalog() { }

    public static Map<String, Object> document(String binarySha256) {
        if (binarySha256 == null || !binarySha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Native primitive catalog requires a binary SHA-256");
        }
        List<Map<String, Object>> models = new ArrayList<>();
        for (Map.Entry<String, ExternalFunctionBase> entry : new TreeMap<>(
                FunctionModelManager.getRegisteredExternalFunctions()).entrySet()) {
            ExternalFunctionBase implementation = entry.getValue();
            boolean release = implementation instanceof FreeFunction;
            if (!release && !(implementation instanceof MallocFunction)
                    && !(implementation instanceof CallocFunction)) { continue; }
            Map<String, Object> model = new LinkedHashMap<>();
            model.put("symbol", entry.getKey());
            model.put("effect", release ? "release" : "return_fresh");
            model.put("argument_index", release ? 0 : null);
            models.add(model);
        }
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("schema_version", "taintsage.memory_primitives.v1");
        document.put("binary_sha256", binarySha256);
        document.put("coverage", "effect_only");
        document.put("models", models);
        return document;
    }

    public static void writeConfigured(String configured, String binarySha256) throws IOException {
        if (configured == null || configured.isBlank()) { return; }
        Map<String, Object> document = document(binarySha256);
        Path output = Path.of(configured).toAbsolutePath();
        Files.createDirectories(output.getParent());
        Path temporary = Files.createTempFile(output.getParent(), output.getFileName() + ".", ".tmp");
        try {
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), document);
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
