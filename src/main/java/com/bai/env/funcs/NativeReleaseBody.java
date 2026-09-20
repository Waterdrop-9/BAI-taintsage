package com.bai.env.funcs;

import com.bai.env.ALoc;
import com.bai.util.GlobalState;
import com.fasterxml.jackson.databind.JsonNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

record NativeReleaseBody(SummaryCondition condition, Address branchSite, Address trueStart,
        Address falseStart, boolean releaseOnTrue) {
    private record PathState(PcodeBlockBasic block, Map<Varnode, Integer> aliases,
            Set<PcodeBlockBasic> visited, int calls, Boolean edge, boolean compared) { }

    static NativeReleaseBody validate(HighFunction high, JsonNode guard, int pointerIndex,
            Varnode pointerStorage, PcodeOp effect) {
        var program = GlobalState.currentProgram;
        Map<Integer, Varnode> parameters = new HashMap<>();
        parameters.put(pointerIndex, pointerStorage);
        SummaryCondition condition = null;
        int guardIndex = -1;
        if (guard != null && !guard.isNull()) {
            require(guard.isObject() && guard.size() == 3 && guard.path("argument_index").isIntegralNumber()
                    && guard.path("argument_index").canConvertToInt(), "Invalid release condition");
            guardIndex = guard.get("argument_index").intValue();
            String operator = guard.path("operator").asText();
            require(Set.of("eq_zero", "ne_zero").contains(operator), "Unsupported release condition operator");
            var prototype = high.getFunctionPrototype();
            require(guardIndex >= 0 && guardIndex != pointerIndex && guardIndex < prototype.getNumParams(),
                    "Condition requires an independent parameter");
            var parameter = prototype.getParam(guardIndex);
            var storage = parameter.getStorage();
            JsonNode observed = guard.path("parameter_storage");
            require(observed.isObject() && observed.size() == 3 && observed.path("byte_length").isIntegralNumber()
                    && observed.path("byte_length").canConvertToInt(), "Invalid condition storage");
            int width = observed.get("byte_length").intValue();
            var register = program.getRegister(observed.path("register_name").asText());
            Address address = program.getAddressFactory().getAddress(observed.path("address").asText());
            require(Set.of(1, 2, 4, 8).contains(width) && parameter.getDataType() instanceof AbstractIntegerDataType
                    && register != null && register.getMinimumByteSize() == width && register.getAddress().equals(address)
                    && parameter.getCategoryIndex() == guardIndex && storage != null
                    && !storage.isAutoStorage() && !storage.isForcedIndirect() && storage.getVarnodeCount() == 1
                    && storage.getFirstVarnode().getAddress().equals(address) && storage.getFirstVarnode().getSize() == width,
                    "Native condition parameter recovery disagrees with summary");
            Varnode location = new Varnode(address, width);
            require(location.getOffset() + width <= pointerStorage.getOffset()
                    || pointerStorage.getOffset() + pointerStorage.getSize() <= location.getOffset(),
                    "Condition overlaps release parameter storage");
            parameters.put(guardIndex, location);
            condition = new SummaryCondition(ALoc.getALoc(location), operator.equals("eq_zero"));
        }
        var blocks = high.getBasicBlocks();
        require(!blocks.isEmpty(), "Native release body is empty");
        PcodeOp comparison = null;
        PcodeOp branch = null;
        PcodeBlockBasic branchBlock = null;
        int calls = 0;
        for (var block : blocks) {
            var operations = block.getIterator();
            while (operations.hasNext()) {
                var operation = operations.next();
                int opcode = operation.getOpcode();
                if (opcode == PcodeOp.CALL) { calls++; }
                if (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL) {
                    require(comparison == null, "Multiple native conditions");
                    comparison = operation;
                }
                if (opcode == PcodeOp.CBRANCH) {
                    require(branch == null, "Multiple native branches");
                    branch = operation;
                    branchBlock = block;
                }
            }
        }
        require(calls == 1 && (condition == null ? branch == null && comparison == null : branch != null && comparison != null),
                "Native control flow disagrees with release condition");
        if (condition != null) {
            require(branch.getNumInputs() == 2 && comparison.getOutput() != null
                    && branch.getInput(1).equals(comparison.getOutput()) && comparison.getOutput().getSize() == 1
                    && !comparison.getOutput().isPersistent(), "Unsupported native condition flow");
        }
        var pending = new ArrayDeque<PathState>();
        pending.add(new PathState(blocks.get(0), new HashMap<>(), Set.of(), 0, null, false));
        Set<PcodeBlockBasic> reached = new HashSet<>();
        Map<Boolean, Integer> outcomes = new HashMap<>();
        while (!pending.isEmpty()) {
            var state = pending.removeFirst();
            var block = state.block();
            require(blocks.contains(block) && !state.visited().contains(block), "Cyclic or foreign native control flow");
            var visited = new HashSet<>(state.visited());
            visited.add(block);
            reached.add(block);
            var aliases = new HashMap<>(state.aliases());
            int count = state.calls();
            boolean returned = false;
            boolean compared = state.compared();
            var operations = block.getIterator();
            while (operations.hasNext()) {
                PcodeOp operation = operations.next();
                int opcode = operation.getOpcode();
                if (opcode == PcodeOp.RETURN) {
                    require(!operations.hasNext() && block.getOutSize() == 0 && operation.getNumInputs() == 1
                            && operation.getOutput() == null, "Unsupported native return");
                    returned = true;
                } else if (opcode == PcodeOp.CALL) {
                    require(++count == 1 && operation.getSeqnum().getTarget().equals(effect.getSeqnum().getTarget())
                            && operation.getNumInputs() == 2 && operation.getOutput() == null
                            && operation.getInput(0).getAddress().equals(effect.getInput(0).getAddress()),
                            "Native call disagrees with release summary");
                    require(origin(operation.getInput(1), aliases, parameters) == pointerIndex,
                            "Native release does not use the selected parameter");
                } else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                    require(operation.getNumInputs() == 1 && operation.getOutput() != null
                            && !operation.getOutput().isPersistent()
                            && operation.getOutput().getSize() == operation.getInput(0).getSize(),
                            "Unsupported native parameter alias");
                    int source = origin(operation.getInput(0), aliases, parameters);
                    require(source >= 0, "Native alias has an unsupported origin");
                    aliases.put(operation.getOutput(), source);
                } else if (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL) {
                    require(condition != null && operation.getNumInputs() == 2, "Unsupported native comparison");
                    Varnode value = operation.getInput(0), zero = operation.getInput(1);
                    if (value.isConstant()) { Varnode swap = value; value = zero; zero = swap; }
                    require(zero.isConstant() && zero.getOffset() == 0 && zero.getSize() == value.getSize()
                            && origin(value, aliases, parameters) == guardIndex, "Native comparison is not the selected integer against zero");
                    compared = true;
                } else if (opcode == PcodeOp.CBRANCH) {
                    require(compared && !operations.hasNext() && block.getOutSize() == 2 && operation.getOutput() == null,
                            "Unsupported native conditional branch");
                } else if (opcode == PcodeOp.BRANCH) {
                    require(!operations.hasNext() && block.getOutSize() == 1 && operation.getNumInputs() == 1
                            && operation.getOutput() == null, "Unsupported native branch");
                } else {
                    throw new IllegalArgumentException("Native body contains unsupported effects");
                }
            }
            if (returned) {
                require(outcomes.put(state.edge(), count) == null, "Ambiguous native path outcome");
            } else {
                require(block.getOutSize() == 1 || block == branchBlock && block.getOutSize() == 2,
                        "Native release body is incomplete");
                for (int edge = 0; edge < block.getOutSize(); edge++) {
                    pending.add(new PathState((PcodeBlockBasic) block.getOut(edge), aliases, visited, count,
                            block == branchBlock ? edge == 1 : state.edge(), compared));
                }
            }
        }
        require(reached.size() == blocks.size(), "Unreachable native summary blocks");
        if (condition == null) {
            require(outcomes.size() == 1 && Integer.valueOf(1).equals(outcomes.get(null)), "Incomplete native release body");
            return new NativeReleaseBody(null, null, null, null, false);
        }
        require(outcomes.size() == 2 && outcomes.containsKey(true) && outcomes.containsKey(false)
                && outcomes.get(true) + outcomes.get(false) == 1, "Release is not controlled by the selected condition");
        boolean releaseOnTrue = outcomes.get(true) == 1;
        require(condition.releaseOnZero() == (releaseOnTrue == (comparison.getOpcode() == PcodeOp.INT_EQUAL)),
                "Native release condition direction disagrees with summary");
        return new NativeReleaseBody(condition, branch.getSeqnum().getTarget(), branchBlock.getTrueOut().getStart(),
                branchBlock.getFalseOut().getStart(), releaseOnTrue);
    }

    private static int origin(Varnode value, Map<Varnode, Integer> aliases, Map<Integer, Varnode> parameters) {
        Integer alias = aliases.get(value);
        if (alias != null) { return alias; }
        if (!value.isInput() || value.getDef() != null || !(value.getHigh() instanceof HighParam parameter)) { return -1; }
        Varnode storage = parameters.get(parameter.getSlot());
        return storage != null && value.getAddress().equals(storage.getAddress()) && value.getSize() == storage.getSize()
                ? parameter.getSlot() : -1;
    }

    private static void require(boolean valid, String reason) {
        if (!valid) { throw new IllegalArgumentException(reason); }
    }
}
