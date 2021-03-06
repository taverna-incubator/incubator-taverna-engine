package net.sf.taverna.t2.provenance.reporter;

import java.util.List;

import net.sf.taverna.t2.invocation.InvocationContext;
import net.sf.taverna.t2.provenance.item.ProvenanceItem;
import net.sf.taverna.t2.provenance.item.WorkflowProvenanceItem;
import net.sf.taverna.t2.reference.ReferenceService;

public interface ProvenanceReporter {
	/**
	 * Add a {@link ProvenanceItem} to the connector
	 * 
	 * @param provenanceItem
	 * @param invocationContext
	 */
	void addProvenanceItem(ProvenanceItem provenanceItem);

	// FIXME is this reference service really needed since we have the context?
	/**
	 * Tell the connector what {@link ReferenceService} it should use when
	 * trying to dereference data items inside {@link ProvenanceItem}s
	 * 
	 * @param referenceService
	 */
	void setReferenceService(ReferenceService referenceService);

	/**
	 * Get the {@link ReferenceService} in use by this connector
	 * 
	 * @return
	 */
	ReferenceService getReferenceService();

	/**
	 * Get all the {@link ProvenanceItem}s that the connector currently knows
	 * about
	 * 
	 * @return
	 */
	List<ProvenanceItem> getProvenanceCollection();

	/**
	 * Set the {@link InvocationContext} that this reporter should be using
	 * 
	 * @param invocationContext
	 */
	void setInvocationContext(InvocationContext invocationContext);

	/**
	 * Get the {@link InvocationContext} that this reporter should be using if
	 * it needs to dereference any data
	 * 
	 * @return
	 */
	InvocationContext getInvocationContext();

	/**
	 * A unique identifier for this run of provenance, should correspond to the
	 * initial {@link WorkflowProvenanceItem} idenifier that gets sent through
	 * 
	 * @param identifier
	 */
	void setSessionID(String sessionID);

	/**
	 * What is the unique identifier used by this connector
	 * 
	 * @return
	 */
	String getSessionID();
}
