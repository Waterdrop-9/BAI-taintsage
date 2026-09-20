package com.bai.env.funcs;

import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.HashMap;
import java.util.Map;

final class SummaryMachineEffects {
    private record PathState(Address address, Map<Varnode, Long> offsets, Set<Address> visited,
            int calls, Integer expectedCalls) { }

    static void validate(Function function, Address releaseSite, PrototypeModel convention, int stackPop,
            NativeReleaseBody body) {
        var program = GlobalState.currentProgram;
        var register = program.getCompilerSpec().getStackPointer();
        Varnode stack = new Varnode(register.getAddress(), register.getMinimumByteSize());
        int width = stack.getSize();
        Map<Varnode, Long> offsets = new HashMap<>();
        offsets.put(stack, 0L);
        Map<Address, Instruction> instructions = new HashMap<>();
        for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
            instructions.put(instruction.getAddress(), instruction);
        }
        var pending = new ArrayDeque<PathState>();
        pending.add(new PathState(function.getEntryPoint(), offsets, Set.of(), 0, body.condition() == null ? 1 : null));
        Set<Address> reached = new HashSet<>();
        int exits = 0;
        while (!pending.isEmpty()) {
            var state = pending.removeFirst();
            Instruction instruction = instructions.get(state.address());
            require(instruction != null && !state.visited().contains(state.address()), "Cyclic or incomplete machine body");
            var visited = new HashSet<>(state.visited());
            visited.add(state.address());
            reached.add(state.address());
            offsets = new HashMap<>(state.offsets());
            int calls = state.calls();
            boolean terminal = false;
            Address next = instruction.getFallThrough();
            offsets.keySet().removeIf(Varnode::isUnique);
            PcodeOp[] raw = instruction.getPcode();
            for (int position = 0; position < raw.length; position++) {
                PcodeOp operation = raw[position];
                int opcode = operation.getOpcode();
                require(opcode != PcodeOp.UNIMPLEMENTED && opcode != PcodeOp.BRANCHIND
                        && opcode != PcodeOp.CALLIND && opcode != PcodeOp.CALLOTHER,
                        "Unsupported machine control or user operation");
                for (int index = 0; index < operation.getNumInputs(); index++) {
                    require(!operation.getInput(index).isAddress() || (opcode == PcodeOp.CALL || opcode == PcodeOp.CBRANCH || opcode == PcodeOp.BRANCH) && index == 0,
                            "Unsupported direct machine memory input");
                }
                require(operation.getOutput() == null || !operation.getOutput().isAddress(),
                        "Unsupported direct machine memory output");
                if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                    Long offset = offsets.get(operation.getInput(1));
                    Long depth = offsets.get(stack);
                    int length = opcode == PcodeOp.LOAD ? operation.getOutput().getSize() : operation.getInput(2).getSize();
                    boolean returnRead = opcode == PcodeOp.LOAD && instruction.getFlowType().isTerminal()
                            && offset != null && offset == 0 && length == width && stackPop == width;
                    require(operation.getInput(0).getOffset() == program.getAddressFactory().getDefaultAddressSpace().getSpaceID()
                            && offset != null && depth != null && offset >= depth
                            && (returnRead || offset < 0 && offset <= -length),
                            "Machine memory access is not confined to the private stack frame");
                }
                if (opcode == PcodeOp.CALL) {
                    require(++calls == 1 && instruction.getAddress().equals(releaseSite),
                            "Machine call is not the verified release");
                    Map<Varnode, Long> saved = new HashMap<>();
                    for (Varnode location : convention.getUnaffectedList()) {
                        if (offsets.containsKey(location)) { saved.put(location, offsets.get(location)); }
                    }
                    Long depth = offsets.get(stack);
                    offsets.clear();
                    offsets.putAll(saved);
                    if (depth != null) { offsets.put(stack, Math.addExact(depth, stackPop)); }
                }
                if (opcode == PcodeOp.RETURN) {
                    require(position == raw.length - 1 && !terminal && Long.valueOf(stackPop).equals(offsets.get(stack))
                            && state.expectedCalls() != null && calls == state.expectedCalls(),
                            "Machine return disagrees with stack or release path");
                    terminal = true;
                    exits++;
                }
                if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
                    require(position == raw.length - 1 && operation.getInput(0).isAddress() && !terminal,
                            "Unsupported machine local branch");
                    Address target = operation.getInput(0).getAddress();
                    if (opcode == PcodeOp.CBRANCH) {
                        require(body.condition() != null && instruction.getAddress().equals(body.branchSite())
                                && state.expectedCalls() == null, "Machine condition disagrees with native guard");
                        boolean taken = highEdge(target, instructions, body);
                        boolean fallthrough = highEdge(instruction.getFallThrough(), instructions, body);
                        require(taken != fallthrough, "Machine conditional edges are ambiguous");
                        pending.add(new PathState(target, new HashMap<>(offsets), visited, calls,
                                taken == body.releaseOnTrue() ? 1 : 0));
                        pending.add(new PathState(instruction.getFallThrough(), new HashMap<>(offsets), visited, calls,
                                fallthrough == body.releaseOnTrue() ? 1 : 0));
                        terminal = true;
                    } else {
                        next = target;
                    }
                }
                Varnode output = operation.getOutput();
                if (output == null) { continue; }
                Long offset = null;
                if (output.getSize() == width && operation.getNumInputs() > 0 && operation.getInput(0).getSize() == width) {
                    Long input = offsets.get(operation.getInput(0));
                    if (opcode == PcodeOp.COPY) {
                        offset = input;
                    } else if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB)
                            && input != null && operation.getInput(1).isConstant()) {
                        long constant = operation.getInput(1).getOffset();
                        int shift = 64 - operation.getInput(1).getSize() * 8;
                        constant = (constant << shift) >> shift;
                        offset = opcode == PcodeOp.INT_ADD ? Math.addExact(input, constant) : Math.subtractExact(input, constant);
                    }
                }
                offsets.keySet().removeIf(location -> location.getAddress().getAddressSpace().equals(output.getAddress().getAddressSpace())
                        && location.getOffset() < output.getOffset() + output.getSize()
                        && output.getOffset() < location.getOffset() + location.getSize());
                if (offset != null) {
                    require(width == 8 || width == 4 && offset >= Integer.MIN_VALUE && offset <= Integer.MAX_VALUE,
                            "Stack offset exceeds native pointer width");
                    offsets.put(output, offset);
                }
            }
            if (!terminal) { pending.add(new PathState(next, offsets, visited, calls, state.expectedCalls())); }
        }
        require(exits == (body.condition() == null ? 1 : 2) && reached.equals(instructions.keySet()),
                "Incomplete machine release paths");
    }

    private static boolean highEdge(Address address, Map<Address, Instruction> instructions, NativeReleaseBody body) {
        Set<Address> visited = new HashSet<>();
        while (address != null && visited.add(address)) {
            if (address.equals(body.trueStart())) { return true; }
            if (address.equals(body.falseStart())) { return false; }
            Instruction instruction = instructions.get(address);
            require(instruction != null && instruction.getPcode().length == 0,
                    "Machine branch cannot be bound to high control flow");
            address = instruction.getFallThrough();
        }
        throw new IllegalArgumentException("Incomplete machine branch target");
    }

    private static void require(boolean valid, String reason) {
        if (!valid) { throw new IllegalArgumentException(reason); }
    }
}
