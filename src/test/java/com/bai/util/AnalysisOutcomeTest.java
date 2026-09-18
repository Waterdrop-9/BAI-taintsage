package com.bai.util;

import com.bai.env.Context;
import org.junit.Test;
import static org.junit.Assert.*;

public class AnalysisOutcomeTest {
    @Test
    public void expiredDeadlineIsPartialEvenWithoutCandidates() {
        AnalysisOutcome outcome = Context.mainLoopTimeout(null, 0);
        assertEquals("partial", outcome.getStatus());
        assertEquals("timeout", outcome.getDiagnostics().get(0).get("reason"));
        assertEquals("completed", Context.mainLoopTimeout(null, 1).getStatus());
    }

    @Test
    public void failureCarriesReason() {
        AnalysisOutcome outcome = AnalysisOutcome.failed("missing_entry", "no entry");
        assertEquals("failed", outcome.getStatus());
        assertEquals("missing_entry", outcome.getDiagnostics().get(0).get("reason"));
    }
}
