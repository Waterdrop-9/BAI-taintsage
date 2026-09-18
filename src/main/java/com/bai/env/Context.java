// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.env;

import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Local;
import com.bai.solver.CFG;
import com.bai.solver.PcodeVisitor;
import com.bai.solver.Worklist;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.util.GlobalState;
import java.util.Stack;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import com.bai.util.AnalysisOutcome;


/** Context **/
public class Context {

    private static final Map<Context, Context> pool = new HashMap<>();

    private static Context current;
    private static Long deadlineNanos;

    private static void checkDeadline() {
        if (Thread.currentThread().isInterrupted()) {
            throw new AnalysisInterrupted();
        }
        if (deadlineNanos != null && System.nanoTime() - deadlineNanos >= 0) {
            throw new AnalysisTimedOut();
        }
    }

    private static final class AnalysisTimedOut extends RuntimeException { }
    private static final class AnalysisInterrupted extends RuntimeException { }

    private static Stack<Context> active = new Stack<>();

    private static Stack<Context> pending = new Stack<>();

    private Function function;

    private long[] callstring = new long[GlobalState.config.getCallStringK()]; // default value is zeroes

    private Function[] funcs = new Function[GlobalState.config.getCallStringK()];

    private final Map<Address, AbsEnvPartitions> inValues = new HashMap<>();

    private final Map<Address, AbsEnv> outValues = new HashMap<>();

    private final ContextInputs inputs = new ContextInputs(AbsEnvPartitions.DEFAULT_LIMIT);

    public record Invocation(int input, boolean updated) { }

    private Worklist worklist;

    private Context(Function function) {
        this.function = function;
        this.worklist = new Worklist(CFG.getCFG(function));
    }

    private Context(Function function, long[] callString) {
        this.function = function;
        this.callstring = callString;
        this.worklist = new Worklist(CFG.getCFG(function));
    }

    /**
     * Get a map with addresses and their "before" abstract environments under this context
     */
    public Map<Address, AbsEnv> getAbsEnvIn() {
        Map<Address, AbsEnv> joined = new HashMap<>();
        inValues.forEach((address, states) -> joined.put(address, states.joined()));
        return Map.copyOf(joined);
    }

    /**
     * Get a map with addresses and their "after" abstract environments under this context
     */
    public Map<Address, AbsEnv> getAbsEnvOut() {
        return outValues;
    }

    /**
     * Getter for function field in Context
     */
    public Function getFunction() {
        return function;
    }

    /**
     * Getter for call string field in Context
     */
    public long[] getCallString() {
        return callstring;
    }

    /**
     * @hidden
     * @deprecated Not recommended to use. To be removed
     */
    public Function[] getFuncs() {
        return funcs;
    }

    /**
     * @hidden
    */
    public static Map<Context, Context> getPool() {
        return pool;
    }

    public AbsEnv getExitValue(Invocation invocation) { return inputs.getExit(invocation.input()); }

    public boolean returnFrom(AbsEnv state) { return inputs.returnFrom(state); }

    /**
     * Set the "before" abstract environment for an address under this context
     */
    public void setValueBefore(Address addr, AbsEnv env) {
        assert (env != null);
        AbsEnvPartitions states = new AbsEnvPartitions(AbsEnvPartitions.DEFAULT_LIMIT);
        states.add(env);
        inValues.put(addr, states);
    }

    /**
     * Set the "after" abstract environment for an address under this context
     */
    public void setValueAfter(Address addr, AbsEnv env) {
        assert (env != null);
        outValues.put(addr, env);
    }

    /**
     * Get the abstract environment before an address under this context
     */
    public AbsEnv getValueBefore(Address addr) {
        AbsEnvPartitions states = inValues.get(addr);
        return states == null ? new AbsEnv() : states.joined();
    }

    public List<AbsEnv> getStatesBefore(Address address) {
        AbsEnvPartitions states = inValues.get(address);
        return states == null ? List.of() : states.states();
    }

    public boolean propagateBefore(Address address, AbsEnv env) {
        AbsEnvPartitions states = inValues.computeIfAbsent(address,
                ignored -> new AbsEnvPartitions(AbsEnvPartitions.DEFAULT_LIMIT));
        boolean wasSummarized = states.isSummarized();
        if (!states.add(env)) { return false; }
        if (!wasSummarized && states.isSummarized()) {
            com.bai.util.MemoryEvidenceExporter.recordGap("path_partition_limit", null,
                    new MemoryEvent(address, this, -1, "state_merge"));
        }
        insertToWorklist(address);
        return true;
    }

    /**
     * Get the abstract environment after an address under this context
     */
    public AbsEnv getValueAfter(Address addr) {
        if (outValues.containsKey(addr)) {
            return outValues.get(addr);
        }
        return null;
    }

    public KSet getOldSpKSet(AbsEnv state) {
        return state.getCallerStack() == null ? new KSet(GlobalState.arch.getDefaultPointerSize() * 8)
                : state.getCallerStack();
    }

    private void updateSP(AbsEnv inOutEnv) {
        ALoc spALoc = ALoc.getSPALoc();
        Local local = Local.getLocal(getFunction());
        KSet spKSet = new KSet(GlobalState.arch.getDefaultPointerSize() * 8);
        spKSet = spKSet.insert(AbsVal.getPtr(local));
        inOutEnv.set(spALoc, spKSet, true);
    }

    /**
     * Get partial call string from the original one after poping the latest call site
     */
    public long[] popLast() {
        long[] cs = this.callstring;
        long[] res = new long[GlobalState.config.getCallStringK()];
        System.arraycopy(cs, 0, res, 1, GlobalState.config.getCallStringK() - 1);
        return res;
    }

    /**
     * Taint argc and argv for main function
     */
    public void prepareMainAbsEnv(AbsEnv absEnv, Function mainFunction) {
        final long TAINT_ARGV_COUNT = 5;
        Utils.defineMainFunctionSignature(mainFunction);

        Local entryLocal = Local.getLocal(GlobalState.eEntryFunction);

        // Temporarily set sp point to start
        ALoc spALoc = ALoc.getSPALoc();
        final KSet mainSP = absEnv.get(spALoc);
        KSet tmpSP = new KSet(GlobalState.arch.getDefaultPointerSize() * 8).insert(AbsVal.getPtr(entryLocal));
        absEnv.set(spALoc, tmpSP, true);

        // Set argc to TOP
        List<ALoc> argcALocs = ExternalFunctionBase.getParamALocs(mainFunction, 0, absEnv);
        if (argcALocs.size() != 1) {
            Logging.error("Multiple ALoc for argc.");
            return;
        }
        ALoc argcALoc = argcALocs.get(0);
        if (argcALoc.getRegion().isLocal()) {
            argcALoc = ALoc.getALoc(entryLocal, argcALoc.getBegin(), argcALoc.getLen());
        }
        absEnv.set(argcALoc, KSet.getTop(), true);

        // Set argv to TOP with taint
        List<ALoc> argvALocs = ExternalFunctionBase.getParamALocs(mainFunction, 1, absEnv);
        if (argvALocs.size() != 1) {
            Logging.error("Multiple ALoc for argv.");
            return;
        }
        ALoc argvALoc = argvALocs.get(0);
        long offset;
        if (argvALoc.getRegion().isLocal()) {
            argvALoc = ALoc.getALoc(entryLocal, argvALoc.getBegin(), argcALoc.getLen());
            offset = argvALoc.getBegin() + argvALoc.getLen();
        } else {
            offset = entryLocal.getBase();
        }
        long taints = TaintMap.getTaints(null, this, GlobalState.eEntryFunction);
        int unit = GlobalState.arch.getDefaultPointerSize();
        for (int i = 0; i < TAINT_ARGV_COUNT; i++) {
            absEnv.set(ALoc.getALoc(entryLocal, offset + ((long) i * unit), unit), KSet.getTop(taints), true);
        }

        KSet argvPtrKSet = new KSet(argvALoc.getLen() * 8).insert(AbsVal.getPtr(entryLocal, offset));
        absEnv.set(argvALoc, argvPtrKSet, true);
        // reset sp
        absEnv.set(spALoc, mainSP, true);
    }

    /**
     * Initialize necessary dataflow facts inside a created context
     * @param caller New abstract environment before entrance into this context
     * @param isMain Indicate whether this is a context for conventional "main" functions
     */
    public Invocation initContext(AbsEnv caller, boolean isMain) {
        Function callee = getFunction();
        Address entry = callee.getEntryPoint();
        AbsEnv env = new AbsEnv(caller);
        if (isMain) {
            KSet entryStack = new KSet(GlobalState.arch.getDefaultPointerSize() * 8)
                    .insert(AbsVal.getPtr(Local.getLocal(GlobalState.eEntryFunction)));
            KSet joined = env.get(ALoc.getSPALoc()).join(entryStack);
            if (joined != null) { env.set(ALoc.getSPALoc(), joined, true); }
        }
        int input = inputs.register(env);
        env.setCallInputs(java.util.Set.of(input));
        env.setCallerStack(inputs.getCallerStack(env.getCallInputs(), GlobalState.arch.getDefaultPointerSize() * 8));
        if (env.getCallerStack().isTop()) {
            env.markFlowGap("unresolved_caller_stack");
            com.bai.util.MemoryEvidenceExporter.recordGap("unresolved_caller_stack", null,
                    new MemoryEvent(entry, this, -1, "gap"));
        }
        if (inputs.isOverflow(input)) {
            env.markFlowGap("call_input_partition_limit");
            com.bai.util.MemoryEvidenceExporter.recordGap("call_input_partition_limit", null,
                    new MemoryEvent(entry, this, -1, "state_merge"));
        }
        updateSP(env);
        if (isMain) {
            prepareMainAbsEnv(env, callee);
        }
        return new Invocation(input, propagateBefore(entry, env));
    }

    /**
     * @hidden
     * Insert an address into the worklist of this context
     */
    public void insertToWorklist(Address addr) {
        Logging.debug("Add inst  @ " + Integer.toHexString((int) addr.getOffset()) + " in " + function.toString());
        worklist.push(addr);
    }

    /**
     * @hidden
     * Iterative process for each address inside worklist of this context
     */
    public void loop() {
        while (!worklist.isEmpty()) {
            checkDeadline();
            Address addr = worklist.pop();
            boolean switchRequested = false;
            for (AbsEnv state : getStatesBefore(addr)) {
                checkDeadline();
                switchRequested |= new PcodeVisitor(this).visit(addr, state);
            }
            if (switchRequested) { return; }
        }
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof Context) {
            Context tmp = (Context) obj;
            return this.function == tmp.function && Arrays.equals(this.callstring, tmp.callstring);
        }
        return false;
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return function.hashCode() + Arrays.hashCode(this.callstring);
    }

    /**
     * @hidden
     */
    @Override
    public String toString() {
        return function.toString() + "["
                + Arrays.stream(callstring).mapToObj(Long::toHexString)
                .collect(Collectors.joining(", ")) + "]";
    }

    /**
     * @hidden
     */
    public static void resetPool() {
        pool.clear();
        active.clear();
        pending.clear();
    }

    /**
     * @hidden
     */
    public static Context getEntryContext(Function entryFunction) {
        Context tmp = new Context(entryFunction);
        Context ctx = pool.get(tmp);
        if (ctx != null) {
            return ctx;
        }
        pool.put(tmp, tmp);
        return tmp;
    }

    /**
     * @hidden
     */    
    public static Context getContext(Context prev, Address callSite, Function tf) {
        Context newCtx = new Context(tf);
        System.arraycopy(prev.callstring, 1, newCtx.callstring, 0, GlobalState.config.getCallStringK() - 1);
        System.arraycopy(prev.funcs, 1, newCtx.funcs, 0, GlobalState.config.getCallStringK() - 1);
        newCtx.callstring[GlobalState.config.getCallStringK() - 1] = callSite.getOffset();
        newCtx.funcs[GlobalState.config.getCallStringK() - 1] = prev.getFunction();
        Context ctx = pool.get(newCtx);
        if (ctx != null) {
            return ctx;
        }
        pool.put(newCtx, newCtx);
        return newCtx;
    }

    /**
     * @hidden
     */
    public static Context getContext(Function tf, long[] callstring) { // only for return use
        Context newCtx = new Context(tf, callstring);
        return pool.get(newCtx);
    }

    /**
     * @hidden
     * @deprecated Improper method for Context class, to be changed
     */
    public static List<Context> getContext(Function function) {
        List<Context> res = new ArrayList<>();
        for (Context context : pool.keySet()) {
            if (context.getFunction().equals(function)) {
                res.add(context);
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public static void pushActive(Context ctx) {
        if (!active.contains(ctx)) {
            active.push(ctx);
        }
    }

    /**
     * @hidden
     */    
    public static void pushPending(Context ctx) {
        if (!pending.contains(ctx)) {
            pending.push(ctx);
        }
    }

    private static Context popActive() {
        if (active.isEmpty()) {
            return null;
        }

        return active.pop();
    }

    private static Context popPending() {
        if (pending.isEmpty()) {
            return null;
        }
        return pending.pop();
    }

    /**
     * @hidden
     */
    public static Context popContext() {
        Context ctx = popActive();
        if (ctx == null) {
            ctx = popPending();
        }
        return ctx;
    }

    /**
     * @hidden
     */    
    public static boolean isWait(Context ctx) {
        return active.contains(ctx) || pending.contains(ctx);
    }

    /**
     * @hidden
     * Main entry to drive interprocedural analysis with an entry context
     */    
    public static void mainLoop(Context entryCtx) {
        current = entryCtx;
        while (current != null) {
            checkDeadline();
            current.loop();
            current = popContext();
            if (current != null) {
                Logging.debug("Switch context: " + current);
            }
        }
    }

    /**
     * @hidden
     * Main entry to drive interprocedural analysis with an entry context and a timer
     */    
    public static AnalysisOutcome mainLoopTimeout(Context entryCtx, long timeout) {
        deadlineNanos = timeout < 0 ? null : System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        try {
            checkDeadline();
            mainLoop(entryCtx);
            checkDeadline();
            return AnalysisOutcome.completed();
        } catch (AnalysisTimedOut error) {
            return AnalysisOutcome.partial("timeout", "Solver deadline exceeded");
        } catch (AnalysisInterrupted error) {
            return AnalysisOutcome.partial("interrupted", "Solver thread interrupted");
        } catch (RuntimeException error) {
            Logging.error(error.toString());
            return AnalysisOutcome.partial("solver_exception", error.toString());
        } finally {
            deadlineNanos = null;
        }
    }

}
