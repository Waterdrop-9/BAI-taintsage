package com.bai.util;

import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.externalfuncs.CallocFunction;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.MallocFunction;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class NativePrimitiveCatalogTest {
    private static final String SHA = "a".repeat(64);

    @Before public void setup() {
        GlobalState.config = new Config();
        assertTrue(Logging.init());
        FunctionModelManager.initAll();
    }

    @Test public void exportsOnlyRegisteredNativeLifetimeModels() {
        Map<String, Object> document = NativePrimitiveCatalog.document(SHA);
        assertEquals("taintsage.memory_primitives.v1", document.get("schema_version"));
        assertEquals(SHA, document.get("binary_sha256"));
        assertEquals("effect_only", document.get("coverage"));
        List<?> models = (List<?>) document.get("models");
        TreeSet<String> expected = new TreeSet<>();
        expected.addAll(new FreeFunction().getSymbols());
        expected.addAll(new MallocFunction().getSymbols());
        expected.addAll(new CallocFunction().getSymbols());
        List<String> actual = new ArrayList<>();
        for (Object item : models) {
            Map<?, ?> model = (Map<?, ?>) item;
            String symbol = (String) model.get("symbol");
            actual.add(symbol);
            Object implementation = FunctionModelManager.getExternalFunction(symbol);
            if (implementation instanceof FreeFunction) {
                assertEquals("release", model.get("effect"));
                assertEquals(0, model.get("argument_index"));
            } else {
                assertTrue(implementation instanceof MallocFunction || implementation instanceof CallocFunction);
                assertEquals("return_fresh", model.get("effect"));
                assertTrue(model.containsKey("argument_index"));
                assertNull(model.get("argument_index"));
            }
        }
        assertEquals(new ArrayList<>(expected), actual);
        assertFalse(actual.contains("realloc"));
        FunctionModelManager.initAll();
        assertEquals(document, NativePrimitiveCatalog.document(SHA));
    }

    @Test public void writesBoundSidecarAndReplacesExistingOutput() throws Exception {
        Path directory = Files.createTempDirectory("native-primitives");
        Path output = directory.resolve("nested/catalog.json");
        try {
            NativePrimitiveCatalog.writeConfigured(output.toString(), SHA);
            ObjectMapper mapper = new ObjectMapper();
            assertEquals(NativePrimitiveCatalog.document(SHA), mapper.readValue(output.toFile(), Map.class));
            String other = "b".repeat(64);
            NativePrimitiveCatalog.writeConfigured(output.toString(), other);
            assertEquals(other, mapper.readTree(output.toFile()).get("binary_sha256").asText());
            try (var entries = Files.list(output.getParent())) {
                assertEquals(List.of(output), entries.toList());
            }
        } finally {
            Files.deleteIfExists(output);
            Files.deleteIfExists(output.getParent());
            Files.deleteIfExists(directory);
        }
    }

    @Test public void defaultRunDoesNotRequireCatalogIdentity() throws Exception {
        NativePrimitiveCatalog.writeConfigured(null, null);
        NativePrimitiveCatalog.writeConfigured("", null);
        NativePrimitiveCatalog.writeConfigured("   ", null);
    }

    @Test public void refusesMissingOrMalformedBinaryIdentity() {
        for (String identity : new String[] {null, "", "1234", "g".repeat(64)}) {
            assertThrows(IllegalArgumentException.class, () -> NativePrimitiveCatalog.document(identity));
        }
    }
}
