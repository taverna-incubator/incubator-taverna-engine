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

import static org.junit.Assert.*;
import net.sf.taverna.t2.workflowmodel.Edit;
import net.sf.taverna.t2.workflowmodel.Edits;
import net.sf.taverna.t2.workflowmodel.processor.activity.AbstractActivity;
import net.sf.taverna.t2.workflowmodel.processor.activity.ActivityConfigurationException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ConfigureActivityEditTest {
	private static Edits edits;

	@BeforeClass
	public static void createEditsInstance() {
		edits = new EditsImpl();
	}

	DummyActivity activity;

	@Before
	public void setup() throws Exception {
		activity = new DummyActivity();
	}

	@Test
	public void testDoEdit() throws Exception {
		String bean = "bob";
		Edit<?> edit = edits.getConfigureActivityEdit(activity, bean);
		edit.doEdit();
		assertTrue(activity.isConfigured);
		assertEquals("bob", activity.getConfiguration());
	}

	@Test
	public void testIsApplied() throws Exception {
		String bean = "bob";
		Edit<?> edit = edits.getConfigureActivityEdit(activity, bean);
		assertFalse(edit.isApplied());
		edit.doEdit();
		assertTrue(edit.isApplied());
	}

	@Test
	public void testSubject() {
		String bean = "bob";
		Edit<?> edit = edits.getConfigureActivityEdit(activity, bean);
		assertEquals(activity, edit.getSubject());
	}

	class DummyActivity extends AbstractActivity<Object> {
		public boolean isConfigured = false;
		public Object configBean = null;

		@Override
		public void configure(Object conf)
				throws ActivityConfigurationException {
			isConfigured = true;
			configBean = conf;
		}

		@Override
		public Object getConfiguration() {
			return configBean;
		}

	}
}
