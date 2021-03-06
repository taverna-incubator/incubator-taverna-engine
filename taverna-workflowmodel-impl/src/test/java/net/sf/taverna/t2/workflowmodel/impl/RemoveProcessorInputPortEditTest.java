/*******************************************************************************
 * Copyright (C) 2007 The University of Manchester   
 * 
 *  Modifications to the initial code base are copyright of their
 *  respective authors, or their employers as appropriate.
 * 
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *    
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *    
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 ******************************************************************************/
package net.sf.taverna.t2.workflowmodel.impl;

import net.sf.taverna.t2.workflowmodel.Edit;
import net.sf.taverna.t2.workflowmodel.Edits;
import net.sf.taverna.t2.workflowmodel.Processor;
import net.sf.taverna.t2.workflowmodel.ProcessorInputPort;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

public class RemoveProcessorInputPortEditTest {
	private static Edits edits;

	@BeforeClass
	public static void createEditsInstance() {
		edits = new EditsImpl();
	}

	private Processor processor;
	private ProcessorInputPort inputPort;
	private Edit<Processor> removeProcessorInputPortEdit;
	
	@Before
	public void setup() throws Exception {
		processor = edits.createProcessor("test");
		inputPort = edits.createProcessorInputPort(processor, "port", 1);
		edits.getAddProcessorInputPortEdit(processor, inputPort).doEdit();
		removeProcessorInputPortEdit = edits.getRemoveProcessorInputPortEdit(processor,inputPort);
	}
	
	@Test
	public void testDoEdit() throws Exception {
		assertFalse(removeProcessorInputPortEdit.isApplied());
		Processor p = removeProcessorInputPortEdit.doEdit();
		assertTrue(removeProcessorInputPortEdit.isApplied());
		assertSame(p,processor);
		assertEquals(0,processor.getInputPorts().size());
	}
		
	@Test
	public void testSubject() throws Exception {
		assertSame(processor,removeProcessorInputPortEdit.getSubject());
		removeProcessorInputPortEdit.doEdit();
		assertSame(processor,removeProcessorInputPortEdit.getSubject());		
	}
}
