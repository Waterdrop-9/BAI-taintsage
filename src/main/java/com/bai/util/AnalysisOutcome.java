package com.bai.util;

import java.util.List;
import java.util.Map;

public final class AnalysisOutcome {
    private final String status;
    private final List<Map<String, String>> diagnostics;

    private AnalysisOutcome(String status, List<Map<String, String>> diagnostics) {
        this.status = status;
        this.diagnostics = List.copyOf(diagnostics);
    }

    public static AnalysisOutcome completed() {
        return new AnalysisOutcome("completed", List.of());
    }

    public static AnalysisOutcome partial(String reason, String detail) {
        return new AnalysisOutcome("partial", List.of(Map.of("reason", reason, "detail", detail)));
    }

    public static AnalysisOutcome failed(String reason, String detail) {
        return new AnalysisOutcome("failed", List.of(Map.of("reason", reason, "detail", detail)));
    }

    public String getStatus() {
        return status;
    }

    public List<Map<String, String>> getDiagnostics() {
        return diagnostics;
    }
}
