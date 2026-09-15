// Modified for TaintSage, 2026-09-15. Distributed under GPL-3.0; see LICENSE.
package com.bai.env.funcs.stdfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import org.junit.Assert;
import org.junit.Test;

public class MapModelTest {

    @Test
    public void usesReferencedKeyWidthInsteadOfPointerWidth() {
        PointerDataType intPointer = new PointerDataType(IntegerDataType.dataType, 8);

        Assert.assertEquals(4, MapModel.getReferencedValueSize(intPointer, 8));
    }

    @Test
    public void fallsBackWhenParameterIsNotATypedPointer() {
        Assert.assertEquals(8, MapModel.getReferencedValueSize(IntegerDataType.dataType, 8));
        Assert.assertEquals(8, MapModel.getReferencedValueSize(PointerDataType.dataType, 8));
    }
}
