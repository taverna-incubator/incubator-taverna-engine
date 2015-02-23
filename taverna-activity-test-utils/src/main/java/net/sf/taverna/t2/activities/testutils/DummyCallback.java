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
package net.sf.taverna.t2.activities.testutils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import net.sf.taverna.t2.invocation.InvocationContext;
import net.sf.taverna.t2.invocation.impl.InvocationContextImpl;
import net.sf.taverna.t2.reference.ReferenceService;
import net.sf.taverna.t2.reference.T2Reference;
import net.sf.taverna.t2.workflowmodel.processor.activity.AsynchronousActivityCallback;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchErrorType;

import org.apache.log4j.Logger;

/**
 * A DummyCallback to aid with testing Activities.
 * 
 * @author Stuart Owen
 * @author David Withers
 * @author Stian Soiland-Reyes
 */
public class DummyCallback implements AsynchronousActivityCallback {
	private static Logger logger = Logger.getLogger(DummyCallback.class);

	public ReferenceService referenceService;
	public InvocationContext invocationContext;
	public Map<String, T2Reference> data;
	public Thread thread;
	public boolean failed = false;
	public List<RuntimeException> failures = new ArrayList<>();
	
	public DummyCallback(ReferenceService referenceService) {
		this.referenceService = referenceService;
		this.invocationContext = new InvocationContextImpl(referenceService, null);
	}

	@Override
	public void fail(String message, Throwable t) {
		fail(message, t, null);
	}

	@Override
	public void fail(String message) {
		fail(message, null, null);
	}

	@Override
	public void fail(String message, Throwable t, DispatchErrorType arg2) {
		failed = true;
		failures.add(new RuntimeException(arg2+message, t));
		logger.error("", t);
	}
	
	/*public SecurityAgentManager getLocalSecurityManager() {
		return null;
	}*/

	@Override
	public void receiveCompletion(int[] completionIndex) {
	}

	@Override
	public void receiveResult(Map<String, T2Reference> data,
			int[] index) {
		this.data = data;
	}

	@Override
	public void requestRun(Runnable runMe) {
		thread = new Thread(runMe);
		thread.start();
	}

	@Override
	public InvocationContext getContext() {
		return invocationContext;
	}

	@Override
	public String getParentProcessIdentifier() {
		return "";
	}
}
