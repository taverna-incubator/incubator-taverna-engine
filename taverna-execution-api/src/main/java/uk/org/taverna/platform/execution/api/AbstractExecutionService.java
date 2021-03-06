/*******************************************************************************
 * Copyright (C) 2010 The University of Manchester
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
package uk.org.taverna.platform.execution.api;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.taverna.robundle.Bundle;

import uk.org.taverna.platform.report.WorkflowReport;
import org.apache.taverna.scufl2.api.container.WorkflowBundle;
import org.apache.taverna.scufl2.api.core.Workflow;
import org.apache.taverna.scufl2.api.profiles.Profile;

/**
 * A common super type for concrete implementations of <code>ExecutionService</code>s.
 *
 * @author David Withers
 */
public abstract class AbstractExecutionService implements ExecutionService {
	private final String ID;
	private final String name;
	private final String description;
	private final Map<String, Execution> executionMap;

	public AbstractExecutionService(String ID, String name, String description) {
		this.ID = ID;
		this.name = name;
		this.description = description;
		executionMap = Collections.synchronizedMap(new HashMap<String, Execution>());
	}

	@Override
	public String getID() {
		return ID;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public String createExecution(ExecutionEnvironment executionEnvironment,
			WorkflowBundle workflowBundle, Workflow workflow, Profile profile,
			Bundle dataBundle) throws InvalidWorkflowException {
		Execution execution = createExecutionImpl(workflowBundle, workflow, profile, dataBundle);
		executionMap.put(execution.getID(), execution);
		return execution.getID();
	}

	/**
	 * Creates an implementation of an Execution.
	 *
	 * To be implemented by concrete implementations of <code>ExecutionService</code>.
	 *
	 * @param workflowBundle
	 *            the <code>WorkflowBundle</code> containing the <code>Workflow</code>s required for
	 *            execution
	 * @param workflow
	 *            the <code>Workflow</code> to execute
	 * @param profile
	 *            the <code>Profile</code> to use when executing the <code>Workflow</code>
	 * @param dataBundle
	 *            the <code>Bundle</code> containing the data values for the <code>Workflow</code>
	 * @return a new Execution implementation
	 * @throws InvalidWorkflowException
	 *             if the specified workflow is invalid
	 */
	protected abstract Execution createExecutionImpl(
			WorkflowBundle workflowBundle, Workflow workflow, Profile profile,
			Bundle dataBundle) throws InvalidWorkflowException;

	@Override
	public WorkflowReport getWorkflowReport(String executionID)
			throws InvalidExecutionIdException {
		return getExecution(executionID).getWorkflowReport();
	}

	@Override
	public void delete(String executionID) throws InvalidExecutionIdException {
		getExecution(executionID).delete();
		executionMap.remove(executionID);
	}

	@Override
	public void start(String executionID) throws InvalidExecutionIdException {
		getExecution(executionID).start();
	}

	@Override
	public void pause(String executionID) throws InvalidExecutionIdException {
		getExecution(executionID).pause();
	}

	@Override
	public void resume(String executionID) throws InvalidExecutionIdException {
		getExecution(executionID).resume();
	}

	@Override
	public void cancel(String executionID) throws InvalidExecutionIdException {
		getExecution(executionID).cancel();
	}

	protected Execution getExecution(String executionID)
			throws InvalidExecutionIdException {
		Execution execution = executionMap.get(executionID);
		if (execution == null)
			throw new InvalidExecutionIdException("Execution ID " + executionID
					+ " is not valid");
		return execution;
	}

}
