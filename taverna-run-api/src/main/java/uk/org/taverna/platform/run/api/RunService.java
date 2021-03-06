package uk.org.taverna.platform.run.api;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.apache.taverna.robundle.Bundle;

import uk.org.taverna.platform.execution.api.ExecutionEnvironment;
import uk.org.taverna.platform.execution.api.InvalidExecutionIdException;
import uk.org.taverna.platform.execution.api.InvalidWorkflowException;
import uk.org.taverna.platform.report.State;
import uk.org.taverna.platform.report.WorkflowReport;
import org.apache.taverna.scufl2.api.container.WorkflowBundle;
import org.apache.taverna.scufl2.api.core.Workflow;
import org.apache.taverna.scufl2.api.profiles.Profile;

/**
 * Service for managing runs of Taverna workflows.
 * 
 * @author David Withers
 */
public interface RunService {
	String EVENT_TOPIC_ROOT = "uk/org/taverna/platform/run/RunService/";
	String RUN_CREATED = EVENT_TOPIC_ROOT + "RUN_CREATED";
	String RUN_DELETED = EVENT_TOPIC_ROOT + "RUN_DELETED";
	String RUN_STARTED = EVENT_TOPIC_ROOT + "RUN_STARTED";
	String RUN_STOPPED = EVENT_TOPIC_ROOT + "RUN_STOPPED";
	String RUN_PAUSED = EVENT_TOPIC_ROOT + "RUN_PAUSED";
	String RUN_RESUMED = EVENT_TOPIC_ROOT + "RUN_RESUMED";
	String RUN_OPENED = EVENT_TOPIC_ROOT + "RUN_OPENED";
	String RUN_CLOSED = EVENT_TOPIC_ROOT + "RUN_CLOSED";

	/**
	 * Returns the available <code>ExecutionEnvironment</code>s.
	 * 
	 * @return the available <code>ExecutionEnvironment</code>s
	 */
	Set<ExecutionEnvironment> getExecutionEnvironments();

	/**
	 * Returns the <code>ExecutionEnvironment</code>s that can execute the
	 * specified <code>WorkflowBundle</code> using its default
	 * <code>Profile</code>.
	 * 
	 * @param workflowBundle
	 *            the <code>WorkflowBundle</code> to find
	 *            <code>ExecutionEnvironment</code>s for
	 * @return the <code>ExecutionEnvironment</code>s that can execute the
	 *         specified <code>WorkflowBundle</code>
	 */
	Set<ExecutionEnvironment> getExecutionEnvironments(
			WorkflowBundle workflowBundle);

	/**
	 * Returns the <code>ExecutionEnvironment</code>s that can execute the
	 * specified <code>Profile</code>.
	 * 
	 * @param profile
	 *            the <code>Profile</code> to find
	 *            <code>ExecutionEnvironment</code>s for
	 * @return the <code>ExecutionEnvironment</code>s that can execute the
	 *         specified <code>Profile</code>
	 */
	Set<ExecutionEnvironment> getExecutionEnvironments(Profile profile);

	/**
	 * Creates a new run and returns the ID for the run.
	 * 
	 * To start the run use the {@link #start(String)} method.
	 * 
	 * @param runProfile
	 *            the workflow to run
	 * @return the run ID
	 * @throws InvalidWorkflowException
	 * @throws RunProfileException
	 */
	String createRun(RunProfile runProfile) throws InvalidWorkflowException,
			RunProfileException;

	/**
	 * Returns the list of runs that this service is managing.
	 * <p>
	 * If there are no runs this method returns an empty list.
	 * 
	 * @return the list of runs that this service is managing
	 */
	List<String> getRuns();

	/**
	 * Opens a run and returns the ID for the run.
	 * 
	 * @param runFile
	 *            the workflow run to open
	 * @return the run ID
	 * @throws InvalidWorkflowException
	 * @throws RunProfileException
	 */
	String open(File runFile) throws IOException;

	/**
	 * Closes a run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws InvalidExecutionIdException
	 */
	void close(String runID) throws InvalidRunIdException,
			InvalidExecutionIdException;

	/**
	 * Saves a run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws InvalidExecutionIdException
	 */
	void save(String runID, File runFile) throws InvalidRunIdException,
			IOException;

	/**
	 * Deletes a run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws InvalidExecutionIdException
	 */
	void delete(String runID) throws InvalidRunIdException,
			InvalidExecutionIdException;

	/**
	 * Starts a run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws RunStateException
	 *             if the run state is not CREATED
	 * @throws InvalidExecutionIdException
	 */
	void start(String runID) throws InvalidRunIdException, RunStateException,
			InvalidExecutionIdException;

	/**
	 * Pauses a running run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws RunStateException
	 *             if the run state is not RUNNING
	 * @throws InvalidExecutionIdException
	 */
	void pause(String runID) throws InvalidRunIdException, RunStateException,
			InvalidExecutionIdException;

	/**
	 * Resumes a paused run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws RunStateException
	 *             if the run state is not PAUSED
	 * @throws InvalidExecutionIdException
	 */
	void resume(String runID) throws InvalidRunIdException, RunStateException,
			InvalidExecutionIdException;

	/**
	 * Cancels a running or paused run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 * @throws RunStateException
	 *             if the run state is not RUNNING or PAUSED
	 * @throws InvalidExecutionIdException
	 */
	void cancel(String runID) throws InvalidRunIdException, RunStateException,
			InvalidExecutionIdException;

	/**
	 * Returns the current state of the run.
	 * 
	 * A run's state can be CREATED, RUNNING, COMPLETED, PAUSED, CANCELLED or
	 * FAILED.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @return the current state of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 */
	State getState(String runID) throws InvalidRunIdException;

	/**
	 * Returns the <code>Bundle</code> containing the data values of the run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @return the <code>Databundle</code> containing the data values of the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 */
	Bundle getDataBundle(String runID) throws InvalidRunIdException;

	/**
	 * Returns the status report for the run.
	 * 
	 * @param runID
	 *            the ID of the run
	 * @return the status report for the run
	 * @throws InvalidRunIdException
	 *             if the run ID is not valid
	 */
	WorkflowReport getWorkflowReport(String runID) throws InvalidRunIdException;

	Workflow getWorkflow(String runID) throws InvalidRunIdException;

	Profile getProfile(String runID) throws InvalidRunIdException;

	String getRunName(String runID) throws InvalidRunIdException;
}