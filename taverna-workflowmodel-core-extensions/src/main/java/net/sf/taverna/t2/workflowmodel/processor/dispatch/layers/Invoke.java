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
package net.sf.taverna.t2.workflowmodel.processor.dispatch.layers;

import static net.sf.taverna.t2.workflowmodel.processor.dispatch.description.DispatchMessageType.ERROR;
import static net.sf.taverna.t2.workflowmodel.processor.dispatch.description.DispatchMessageType.RESULT;
import static net.sf.taverna.t2.workflowmodel.processor.dispatch.description.DispatchMessageType.RESULT_COMPLETION;

import java.lang.Thread.UncaughtExceptionHandler;
import java.sql.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import net.sf.taverna.t2.invocation.InvocationContext;
import net.sf.taverna.t2.monitor.MonitorManager;
import net.sf.taverna.t2.monitor.MonitorableProperty;
import net.sf.taverna.t2.provenance.item.InvocationStartedProvenanceItem;
import net.sf.taverna.t2.provenance.item.IterationProvenanceItem;
import net.sf.taverna.t2.provenance.reporter.ProvenanceReporter;
import net.sf.taverna.t2.reference.ReferenceService;
import net.sf.taverna.t2.reference.T2Reference;
import net.sf.taverna.t2.workflowmodel.ControlBoundary;
import net.sf.taverna.t2.workflowmodel.OutputPort;
import net.sf.taverna.t2.workflowmodel.processor.activity.Activity;
import net.sf.taverna.t2.workflowmodel.processor.activity.AsynchronousActivity;
import net.sf.taverna.t2.workflowmodel.processor.activity.AsynchronousActivityCallback;
import net.sf.taverna.t2.workflowmodel.processor.activity.MonitorableAsynchronousActivity;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.AbstractDispatchLayer;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.DispatchLayer;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.description.DispatchLayerJobReaction;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchCompletionEvent;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchErrorEvent;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchErrorType;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchJobEvent;
import net.sf.taverna.t2.workflowmodel.processor.dispatch.events.DispatchResultEvent;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Context free invoker layer, does not pass index arrays of jobs into activity
 * instances.
 * <p>
 * This layer will invoke the first invokable activity in the activity list, so
 * any sane dispatch stack will have narrowed this down to a single item list by
 * this point, i.e. by the insertion of a failover layer.
 * <p>
 * Currently only handles activities implementing {@link AsynchronousActivity}.
 *
 * @author Tom Oinn
 * @author Stian Soiland-Reyes
 *
 */
@DispatchLayerJobReaction(emits = { ERROR, RESULT_COMPLETION, RESULT }, relaysUnmodified = false, stateEffects = {})
@ControlBoundary
public class Invoke extends AbstractDispatchLayer<JsonNode> {
	public static final String URI = "http://ns.taverna.org.uk/2010/scufl2/taverna/dispatchlayer/Invoke";
	private static Logger logger = Logger.getLogger(Invoke.class);
	private static Long invocationCount = 0L;

	private MonitorManager monMan;

	private static String getNextProcessID() {
		long count;
		synchronized (invocationCount) {
			count = ++invocationCount;
		}
		return "invocation" + count;
	}

	public Invoke() {
		super();
		monMan = MonitorManager.getInstance();
	}

	@Override
	public void configure(JsonNode config) {
		// No configuration, do nothing
	}

	@Override
	public JsonNode getConfiguration() {
		return null;
	}

	/**
	 * Receive a job from the layer above and pick the first concrete activity
	 * from the list to invoke. Invoke this activity, creating a callback which
	 * will wrap up the result messages in the appropriate collection depth
	 * before sending them on (in general activities are not aware of their
	 * invocation context and should not be responsible for providing correct
	 * index arrays for results)
	 * <p>
	 * This layer will invoke the first invokable activity in the activity list,
	 * so any sane dispatch stack will have narrowed this down to a single item
	 * list by this point, i.e. by the insertion of a failover layer.
	 */
	@Override
	public void receiveJob(final DispatchJobEvent jobEvent) {
		for (Activity<?> activity : jobEvent.getActivities())
			if (activity instanceof AsynchronousActivity) {
				invoke(jobEvent, (AsynchronousActivity<?>) activity);
				break;
			}
	}

	protected void invoke(final DispatchJobEvent jobEvent, final AsynchronousActivity<?> activity) {
		// Register with the monitor
		final String invocationProcessIdentifier = jobEvent.pushOwningProcess(
				getNextProcessID()).getOwningProcess();
		monMan.registerNode(activity, invocationProcessIdentifier,
				new HashSet<MonitorableProperty<?>>());
		monMan.registerNode(jobEvent, invocationProcessIdentifier,
				new HashSet<MonitorableProperty<?>>());

		/*
		 * The activity is an AsynchronousActivity so we invoke it with an
		 * AsynchronousActivityCallback object containing appropriate callback
		 * methods to push results, completions and failures back to the
		 * invocation layer.
		 * 
		 * Get the registered DataManager for this process. In most cases this
		 * will just be a single DataManager for the entire workflow system but
		 * it never hurts to generalize
		 */

		InvocationContext context = jobEvent.getContext();
		final ReferenceService refService = context.getReferenceService();

		InvocationStartedProvenanceItem invocationItem = null;
		ProvenanceReporter provenanceReporter = context.getProvenanceReporter();
		if (provenanceReporter != null) {
			IntermediateProvenance intermediateProvenance = findIntermediateProvenance();
			if (intermediateProvenance != null) {
				invocationItem = new InvocationStartedProvenanceItem();
				IterationProvenanceItem parentItem = intermediateProvenance.getIterationProvItem(jobEvent);
				invocationItem.setIdentifier(UUID.randomUUID().toString());
				invocationItem.setActivity(activity);
				invocationItem.setProcessId(jobEvent.getOwningProcess());
				invocationItem.setInvocationProcessId(invocationProcessIdentifier);
				invocationItem.setParentId(parentItem.getIdentifier());
				invocationItem.setWorkflowId(parentItem.getWorkflowId());
				invocationItem.setInvocationStarted(new Date(System.currentTimeMillis()));
				provenanceReporter.addProvenanceItem(invocationItem);
			}
		}

		/*
		 * Create a Map of EntityIdentifiers named appropriately given the
		 * activity mapping
		 */
		Map<String, T2Reference> inputData = new HashMap<>();
		for (String inputName : jobEvent.getData().keySet()) {
			String activityInputName = activity
					.getInputPortMapping().get(inputName);
			if (activityInputName != null)
				inputData.put(activityInputName, jobEvent.getData()
						.get(inputName));
		}

		/*
		 * Create a callback object to receive events, completions and failure
		 * notifications from the activity
		 */
		AsynchronousActivityCallback callback = new InvokeCallBack(
				jobEvent, refService, invocationProcessIdentifier,
				activity);

		if (activity instanceof MonitorableAsynchronousActivity<?>) {
			/*
			 * Monitorable activity so get the monitorable properties and push
			 * them into the state tree after launching the job
			 */
			MonitorableAsynchronousActivity<?> maa = (MonitorableAsynchronousActivity<?>) activity;
			Set<MonitorableProperty<?>> props = maa
					.executeAsynchWithMonitoring(inputData, callback);
			monMan.addPropertiesToNode(invocationProcessIdentifier.split(":"), props);
		} else {
			/*
			 * Run the job, passing in the callback we've just created along
			 * with the (possibly renamed) input data map
			 */
			activity.executeAsynch(inputData, callback);
		}
	}

	protected IntermediateProvenance findIntermediateProvenance() {
		for (DispatchLayer<?> layer : getProcessor().getDispatchStack()
				.getLayers())
			if (layer instanceof IntermediateProvenance)
				return (IntermediateProvenance) layer;
		return null;
	}

	protected class InvokeCallBack implements AsynchronousActivityCallback {
		protected final AsynchronousActivity<?> activity;
		protected final String invocationProcessIdentifier;
		protected final DispatchJobEvent jobEvent;
		protected final ReferenceService refService;
		protected boolean sentJob = false;

		protected InvokeCallBack(DispatchJobEvent jobEvent,
				ReferenceService refService,
				String invocationProcessIdentifier,
				AsynchronousActivity<?> asyncActivity) {
			this.jobEvent = jobEvent;
			this.refService = refService;
			this.invocationProcessIdentifier = invocationProcessIdentifier;
			this.activity = asyncActivity;
		}

		@Override
		public void fail(String message) {
			fail(message, null);
		}

		@Override
		public void fail(String message, Throwable t) {
			fail(message, t, DispatchErrorType.INVOCATION);
		}

		@Override
		public void fail(String message, Throwable t,
				DispatchErrorType errorType) {
			logger.warn("Failed (" + errorType + ") invoking " + activity
					+ " for job " + jobEvent + ": " + message, t);
			monMan.deregisterNode(
					invocationProcessIdentifier);
			getAbove().receiveError(
					new DispatchErrorEvent(jobEvent.getOwningProcess(),
							jobEvent.getIndex(), jobEvent.getContext(),
							message, t, errorType, activity));
		}

		@Override
		public InvocationContext getContext() {
			return jobEvent.getContext();
		}

		@Override
		public String getParentProcessIdentifier() {
			return invocationProcessIdentifier;
		}

		@Override
		public void receiveCompletion(int[] completionIndex) {
			if (completionIndex.length == 0)
				// Final result, clean up monitor state
				monMan.deregisterNode(invocationProcessIdentifier);
			if (sentJob) {
				int[] newIndex;
				if (completionIndex.length == 0)
					newIndex = jobEvent.getIndex();
				else {
					newIndex = new int[jobEvent.getIndex().length
							+ completionIndex.length];
					int i = 0;
					for (int indexValue : jobEvent.getIndex())
						newIndex[i++] = indexValue;
					for (int indexValue : completionIndex)
						newIndex[i++] = indexValue;
				}
				DispatchCompletionEvent c = new DispatchCompletionEvent(
						jobEvent.getOwningProcess(), newIndex, jobEvent
								.getContext());
				getAbove().receiveResultCompletion(c);
			} else {
				/*
				 * We haven't sent any 'real' data prior to completing a stream.
				 * This in effect means we're sending an empty top level
				 * collection so we need to register empty collections for each
				 * output port with appropriate depth (by definition if we're
				 * streaming all outputs are collection types of some kind)
				 */
				Map<String, T2Reference> emptyListMap = new HashMap<>();
				for (OutputPort op : activity.getOutputPorts()) {
					String portName = op.getName();
					int portDepth = op.getDepth();
					emptyListMap.put(portName, refService.getListService()
							.registerEmptyList(portDepth, jobEvent.getContext()).getId());
				}
				receiveResult(emptyListMap, new int[0]);
			}
		}

		@Override
		public void receiveResult(Map<String, T2Reference> data, int[] index) {
			/*
			 * Construct a new result map using the activity mapping (activity
			 * output name to processor output name)
			 */
			Map<String, T2Reference> resultMap = new HashMap<>();
			for (String outputName : data.keySet()) {
				String processorOutputName = activity
						.getOutputPortMapping().get(outputName);
				if (processorOutputName != null)
					resultMap.put(processorOutputName, data.get(outputName));
			}
			/*
			 * Construct a new index array if the specified index is non zero
			 * length, otherwise just use the original job's index array (means
			 * we're not streaming)
			 */
			int[] newIndex;
			boolean streaming = false;
			if (index.length == 0)
				newIndex = jobEvent.getIndex();
			else {
				streaming = true;
				newIndex = new int[jobEvent.getIndex().length + index.length];
				int i = 0;
				for (int indexValue : jobEvent.getIndex())
					newIndex[i++] = indexValue;
				for (int indexValue : index)
					newIndex[i++] = indexValue;
			}
			DispatchResultEvent resultEvent = new DispatchResultEvent(jobEvent
					.getOwningProcess(), newIndex, jobEvent.getContext(),
					resultMap, streaming);
			if (!streaming) {
				monMan.registerNode(resultEvent, invocationProcessIdentifier,
						new HashSet<MonitorableProperty<?>>());
				// Final result, clean up monitor state
				monMan.deregisterNode(invocationProcessIdentifier);
			}
			// Push the modified data to the layer above in the dispatch stack
			getAbove().receiveResult(resultEvent);

			sentJob = true;
		}

		@Override
		public void requestRun(Runnable runMe) {
			String newThreadName = jobEvent.toString();
			Thread thread = new Thread(runMe, newThreadName);
			thread.setContextClassLoader(activity.getClass()
					.getClassLoader());
			thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
				@Override
				public void uncaughtException(Thread t, Throwable e) {
					fail("Uncaught exception while invoking " + activity, e);
				}
			});
			thread.start();
		}
	}
}
