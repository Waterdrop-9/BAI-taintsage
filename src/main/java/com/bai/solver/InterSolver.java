package com.bai.solver;

import com.bai.env.AbsEnv;
import com.bai.util.AnalysisOutcome;
import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

/**
 * The class for interprocedural analysis.
 */
public class InterSolver {

    private Function entry;
    private boolean isMain;

    /**
     * Constructor for InterSolver
     * @param entry The start point function for interprocedural analysis
     * @param isMain The flag to indicate whether the entry is conventional "main" function
     */
    public InterSolver(Function entry, boolean isMain) {
        this.entry = entry;
        this.isMain = isMain;
    }


    /**
     * The driver function for the interprocedural analysis  
     */
    public AnalysisOutcome run() {
        try {
            Context mainContext = Context.getEntryContext(entry);
            mainContext.initContext(new AbsEnv(), isMain);
            return Context.mainLoopTimeout(mainContext, GlobalState.config.getTimeout());
        } catch (RuntimeException error) {
            return AnalysisOutcome.failed("initialization_exception", error.toString());
        }
    }

}
