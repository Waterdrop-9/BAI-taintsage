package com.bai.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.pcode.Varnode;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public class MemorySummariesTest extends ARMProgramTestBase {
    @Test public void rejectsUnsupportedDocumentBeforeInstallingModels() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> MemorySummaries.load(
                "{\"schema_version\":\"wrong\",\"summaries\":[]}".getBytes(StandardCharsets.UTF_8), "a".repeat(64)));
        assertNull(MemorySummaries.report());
    }
    @Test public void foreignBinaryIsRejectedWithoutInstallingOrApplyingModel() throws Exception {
        byte[] content = ("{\"schema_version\":\"taintsage.memory_summaries.v1\",\"summaries\":["
                + "{\"function_entry\":\"ram:1000\",\"binary_sha256\":\"" + "b".repeat(64) + "\"}]}")
                .getBytes(StandardCharsets.UTF_8);
        MemorySummaries.load(content, "a".repeat(64));
        var report = MemorySummaries.report();
        var rows = (java.util.List<?>) report.get("models");
        assertEquals(1, rows.size());
        var row = (java.util.Map<?, ?>) rows.get(0);
        assertEquals("rejected", row.get("status"));
        assertEquals(0, row.get("transfer_evaluations"));
        assertTrue(row.get("reason").toString().contains("binary"));
        MemorySummaries.reset();
        assertNull(MemorySummaries.report());
    }

    @Test public void conditionalDecisionRequiresUniformConcreteIntegerValues() {
        var register = program.getRegister("r1");
        var location = ALoc.getALoc(new Varnode(register.getAddress(), 4));
        var condition = new SummaryCondition(location, false);
        var environment = new AbsEnv();
        assertEquals(SummaryCondition.Decision.DEFER, condition.evaluate(environment));
        environment.set(location, new KSet(32).insert(new AbsVal(0)), true);
        assertEquals(SummaryCondition.Decision.SKIP, condition.evaluate(environment));
        environment.set(location, new KSet(32).insert(new AbsVal(2))
                .insert(new AbsVal(7)), true);
        assertEquals(SummaryCondition.Decision.RELEASE, condition.evaluate(environment));
        environment.set(location, new KSet(32).insert(new AbsVal(0))
                .insert(new AbsVal(7)), true);
        assertEquals(SummaryCondition.Decision.DEFER, condition.evaluate(environment));
        environment.set(location, KSet.getTop(), true);
        assertEquals(SummaryCondition.Decision.DEFER, condition.evaluate(environment));
        environment.set(location, new KSet(32).insert(new AbsVal(Reg.getInstance(), 0)), true);
        assertEquals(SummaryCondition.Decision.DEFER, condition.evaluate(environment));
        var inverse = new SummaryCondition(location, true);
        environment.set(location, new KSet(32).insert(new AbsVal(0)), true);
        assertEquals(SummaryCondition.Decision.RELEASE, inverse.evaluate(environment));
        environment.set(location, new KSet(32).insert(new AbsVal(7)), true);
        assertEquals(SummaryCondition.Decision.SKIP, inverse.evaluate(environment));
    }
}
