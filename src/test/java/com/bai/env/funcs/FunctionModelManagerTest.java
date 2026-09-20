package com.bai.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.funcs.stdfuncs.ListModel;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

public class FunctionModelManagerTest extends ARMProgramTestBase {
    private int nextAddress = 0x1000;

    @Before public void registerModels() { FunctionModelManager.initAll(); }

    private Function function(String namespace, String name, int arity) throws Exception {
        int transaction = program.startTransaction("Create modeled function");
        try {
            Namespace parent = program.getGlobalNamespace();
            for (String part : namespace.split("/")) {
                Namespace existing = program.getSymbolTable().getNamespace(part, parent);
                parent = existing == null ? program.getSymbolTable().createNameSpace(parent, part, SourceType.USER_DEFINED) : existing;
            }
            var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextAddress++);
            Function function = program.getFunctionManager().createFunction(name, parent, address,
                    new AddressSet(address), SourceType.USER_DEFINED);
            for (int i = 0; i < arity; i++) {
                function.addParameter(new ParameterImpl("arg" + i, PointerDataType.dataType, program), SourceType.USER_DEFINED);
            }
            return function;
        } finally { program.endTransaction(transaction, true); }
    }

    @Test public void unsupportedMethodCannotSilentlySucceed() throws Exception {
        Function function = function("std/list<int,allocator<int>>", "clear", 1);
        assertThrows(IllegalArgumentException.class,
                () -> new ListModel().invoke(null, new AbsEnv(), new AbsEnv(), null, function));
    }

    @Test public void namespaceAloneDoesNotSelectAModel() throws Exception {
        assertNull(FunctionModelManager.resolveStd(function("std/__detail/_List_node_base", "_M_hook", 2)));
        assertNull(FunctionModelManager.resolveStd(function("std/list<int,allocator<int>>", "clear", 1)));
        assertNull(FunctionModelManager.resolveStd(function("stdfake/list<int,allocator<int>>", "push_back", 2)));
        assertNull(FunctionModelManager.resolveStd(function("outer/std/list<int,allocator<int>>", "push_back", 2)));
    }

    @Test public void selectsSupportedMethodsAndRejectsUnsupportedArity() throws Exception {
        Object[][] methods = {
            {"list", "list", 1}, {"list", "list", 2}, {"list", "~list", 1},
            {"list", "push_back", 2}, {"list", "back", 1},
            {"map", "map", 1}, {"map", "map", 2}, {"map", "~map", 1}, {"map", "operator[]", 2},
            {"vector", "vector", 1}, {"vector", "vector", 2}, {"vector", "~vector", 1},
            {"vector", "end", 1}, {"vector", "insert", 4}, {"vector", "operator[]", 2}
        };
        for (Object[] method : methods) {
            String namespace = "std/__cxx11/" + method[0] + "<int,allocator<int>>";
            Function supported = function(namespace, (String) method[1], (int) method[2]);
            assertNotNull(supported.toString(), FunctionModelManager.resolveStd(supported));
            Function unsupported = function(namespace, (String) method[1], 0);
            assertNull(unsupported.toString(), FunctionModelManager.resolveStd(unsupported));
        }
        assertNull(FunctionModelManager.resolveStd(function("std/list<int,allocator<int>>", "list", 3)));
    }

    @Test public void resolvedHandlerExecutesTheRealModel() throws Exception {
        Function function = function("std/list<int,allocator<int>>", "list", 1);
        var resolved = FunctionModelManager.resolveStd(function);
        assertNotNull(resolved);
        AbsEnv environment = new AbsEnv();
        resolved.handler().invoke(null, environment, new AbsEnv(), null, function);
        resolved.model().invoke(null, environment, new AbsEnv(), null, function);
    }
}
