package no.s11.w3.prov.taverna.ui;

import java.io.BufferedOutputStream;
import java.sql.Timestamp;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import net.sf.taverna.raven.appconfig.ApplicationConfig;
import net.sf.taverna.t2.provenance.api.ProvenanceAccess;
import net.sf.taverna.t2.provenance.lineageservice.URIGenerator;
import net.sf.taverna.t2.provenance.lineageservice.utils.DataflowInvocation;
import net.sf.taverna.t2.provenance.lineageservice.utils.Port;
import net.sf.taverna.t2.provenance.lineageservice.utils.ProcessorEnactment;
import net.sf.taverna.t2.provenance.lineageservice.utils.ProvenanceProcessor;
import net.sf.taverna.t2.reference.T2Reference;

import org.openrdf.elmo.ElmoModule;
import org.openrdf.elmo.sesame.SesameManager;
import org.openrdf.elmo.sesame.SesameManagerFactory;
import org.openrdf.model.Resource;
import org.openrdf.repository.RepositoryException;
import org.openrdf.repository.contextaware.ContextAwareConnection;
import org.openrdf.rio.RDFHandlerException;
import org.openrdf.rio.helpers.OrganizedRDFWriter;
import org.openrdf.rio.rdfxml.util.RDFXMLPrettyWriter;
import org.w3.provo.Activity;
import org.w3.provo.Agent;
import org.w3.provo.Entity;
import org.w3.provo.Generation;
import org.w3.provo.ProvenanceContainer;
import org.w3.provo.QualifiedInvolvement;
import org.w3.provo.Recipe;
import org.w3.provo.Role;
import org.w3.provo.Usage;

public class W3ProvenanceExport {

	private ProvenanceAccess provenanceAccess;

	private DatatypeFactory datatypeFactory;
	
	public W3ProvenanceExport() {
		try {
			datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new IllegalStateException("Can't find a DatatypeFactory implementation", e);
		}
	}

	private static ProvenanceURIGenerator uriGenerator = new ProvenanceURIGenerator();

	public SesameManager makeElmoManager() {
		ElmoModule module = new ElmoModule(getClass().getClassLoader());
		SesameManagerFactory factory = new SesameManagerFactory(module);
		factory.setInferencingEnabled(true);
		return factory.createElmoManager();
	}

	public W3ProvenanceExport(ProvenanceAccess provenanceAccess) {
		this.setProvenanceAccess(provenanceAccess);
	}

	private static final class ProvenanceURIGenerator extends URIGenerator {


		public String makeDataflowInvocationURI(String workflowRunId,
				String dataflowInvocationId) {
			return makeWFInstanceURI(workflowRunId) + "workflow/" + dataflowInvocationId + "/";
		}

		public String makeProcessExecution(String workflowRunId,
				String processEnactmentId) {
			return makeWFInstanceURI(workflowRunId) + "process/" + processEnactmentId + "/";
		}
	}

	enum Direction {
		INPUTS, OUTPUTS;
	}

	public void exportAsW3Prov(String workflowRunId, BufferedOutputStream outStream)
			throws RepositoryException, RDFHandlerException {

		SesameManager elmoManager = makeElmoManager();
		String runURI = uriGenerator.makeWFInstanceURI(workflowRunId);
		// FIXME: Should this be "" to indicate the current file?
		// FIXME: Should this not be an Account instead?
		ProvenanceContainer provContainer = elmoManager.create(
				new QName(runURI, "provenanceContainer"), ProvenanceContainer.class);
		// TODO: Link provContainer to anything?
		//elmoManager.persist(provContainer);
		
		// Mini-provenance about this provenance trace
 		String versionName = ApplicationConfig.getInstance().getName();
		Agent tavernaAgent = elmoManager.create(
				new QName("http://ns.taverna.org.uk/2011/software/", versionName), Agent.class);
		Activity storeProvenance = elmoManager.create(Activity.class);
		storeProvenance.getProvWasControlledBy().add(tavernaAgent);
		Entity storeProvenanceEnt = elmoManager.designateEntity(storeProvenance, Entity.class);
		storeProvenanceEnt.setProvWasGeneratedBy(storeProvenance);
		// The store-provenance-process used the workflow run as input
		storeProvenance.getProvUsed().add(elmoManager.create(new QName(runURI), Entity.class, Activity.class));
	//	elmoManager.persist(provContainer);
		//elmoManager.persist(storeProvenance);
	
		
		DataflowInvocation dataflowInvocation = provenanceAccess.getDataflowInvocation(workflowRunId);
		//String dataflowURI = uriGenerator.makeDataflowInvocationURI(workflowRunId, dataflowInvocation.getDataflowInvocationId());
		Activity wfProcess = elmoManager.create(new QName(runURI), Activity.class, Agent.class);
		wfProcess.getProvWasControlledBy().add(tavernaAgent);				
		// Recipe
		String wfUri = uriGenerator.makeWorkflowURI(dataflowInvocation.getWorkflowId());
		// TODO: Also make the recipe a Scufl2 Workflow
		Recipe recipe = elmoManager.create(new QName(wfUri), Recipe.class);
		wfProcess.getProvHadRecipe().add(recipe);
		// TODO: start, stop?		
		

		// Workflow inputs and outputs
		storeEntitities(dataflowInvocation.getInputsDataBindingId(), wfProcess,
				Direction.INPUTS, elmoManager);
		// FIXME: These entities come out as "generated" by multiple processes
		storeEntitities(dataflowInvocation.getOutputsDataBindingId(), wfProcess,
				Direction.OUTPUTS, elmoManager);
//		elmoManager.persist(wfProcess);
		
		
		List<ProcessorEnactment> processorEnactments = provenanceAccess
				.getProcessorEnactments(workflowRunId);
		// This will also include processor enactments in nested workflows
		for (ProcessorEnactment pe : processorEnactments) {
			String parentURI = pe.getParentProcessorEnactmentId();
			if (parentURI == null) {
				// Top-level workflow
				parentURI = runURI;
			} else {
				// inside nested wf - this will be parent processenactment
				parentURI = uriGenerator.makeProcessExecution(
						pe.getWorkflowRunId(), pe.getProcessEnactmentId());
			}
			String processURI = uriGenerator.makeProcessExecution(
					pe.getWorkflowRunId(), pe.getProcessEnactmentId());
			Activity process = elmoManager.create(
					new QName(processURI), Activity.class);
			Agent parentProcess = elmoManager.designate(new QName(parentURI), Agent.class, Activity.class);
			process.getProvWasControlledBy().add(parentProcess);
			
			// start/stop			
			GregorianCalendar cal = new GregorianCalendar();
			cal.setTime(pe.getEnactmentStarted());			
			XMLGregorianCalendar started = datatypeFactory.newXMLGregorianCalendar(cal);
			cal.setTime(pe.getEnactmentEnded());
			XMLGregorianCalendar ended = datatypeFactory.newXMLGregorianCalendar(cal);;
			process.getProvStartedAt().getProvInXSDDateTime().add(started);
			process.getProvEndedAt().getProvInXSDDateTime().add(ended);

			// TODO: work out preceeding and controlling from workflow definitions

			
			
			// TODO: Linking to the processor in the workflow definition?			
			ProvenanceProcessor provenanceProcessor = provenanceAccess.getProvenanceProcessor(pe.getProcessorId());			
			String processorURI = uriGenerator.makeProcessorURI(provenanceProcessor.getProcessorName(), provenanceProcessor.getWorkflowId());
			// TODO: Also make the recipe a Scufl2 Processor
			recipe = elmoManager.create(new QName(processorURI), Recipe.class);
			process.getProvHadRecipe().add(recipe);
			

			
			// TODO: How to link together iterations on a single processor and the collections
			// they are iterating over and creating? 
			// Need 'virtual' ProcessExecution for iteration.
			
			// TODO: Activity/service details from definition?
			
			// Inputs and outputs
			storeEntitities(pe.getInitialInputsDataBindingId(), process,
					Direction.INPUTS, elmoManager);
			storeEntitities(pe.getFinalOutputsDataBindingId(), process,
					Direction.OUTPUTS, elmoManager);

//			elmoManager.persist(process);
		}

		// Save the whole thing
		ContextAwareConnection connection = elmoManager.getConnection();
		connection.setNamespace("scufl2",
				"http://ns.taverna.org.uk/2010/scufl2#");
		connection
				.setNamespace("prov", "http://www.w3.org/ns/prov-o/");
		connection.setNamespace("owl", "http://www.w3.org/2002/07/owl#");
		connection.export(new RDFXMLPrettyWriter(outStream));
		//connection.export(new OrganizedRDFWriter(new N3Writer(outStream)));

	}

	private String getProcessorName(String processorId) {		
		ProvenanceProcessor processor = provenanceAccess.getProvenanceProcessor(processorId);
		// TODO: Cache same processorId?
		return processor.getProcessorName();
	}

	private void storeEntitities(String dataBindingId,
			Activity activity, Direction direction,
			SesameManager elmoManager) {

		Map<Port, T2Reference> inputs = provenanceAccess
				.getDataBindings(dataBindingId);
		for (Entry<Port, T2Reference> inputEntry : inputs.entrySet()) {
			Port port = inputEntry.getKey();
			T2Reference t2Ref = inputEntry.getValue();

			String dataURI = uriGenerator.makeT2ReferenceURI(t2Ref.toUri()
					.toASCIIString());

			Entity entity = elmoManager
					.create(new QName(dataURI), Entity.class);

			if (direction == Direction.INPUTS) {
				activity.getProvUsed().add(entity);
			} else {
				entity.setProvWasGeneratedBy(activity);
				// No equivalent inverse property in activity
			}
			
			QualifiedInvolvement involvement;
			if (direction == Direction.INPUTS) {
				involvement = elmoManager.create(Usage.class);
				activity.getProvHadQualifiedUsage().add((Usage)involvement);
			} else {
				involvement = elmoManager.create(Generation.class);
				activity.getProvHadQualifiedGeneration().add((Generation)involvement);
			}
			involvement.getProvHadQualifiedEntity().add(entity);

			String portURI = uriGenerator.makePortURI(port.getWorkflowId(),
					port.getProcessorName(), port.getPortName(),
					port.isInputPort());
			Role portRole = elmoManager.create(new QName(portURI), Role.class);			
			involvement.getProvHadRole().add(portRole);

//			elmoManager.persist(entity);
		}

	}

	public ProvenanceAccess getProvenanceAccess() {
		return provenanceAccess;
	}

	public void setProvenanceAccess(ProvenanceAccess provenanceAccess) {
		this.provenanceAccess = provenanceAccess;
	}

}
