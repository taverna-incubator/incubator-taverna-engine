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
package net.sf.taverna.t2.workflowmodel.processor.activity.config;

import java.util.ArrayList;
import java.util.List;

import net.sf.taverna.t2.workflowmodel.processor.activity.Activity;
import net.sf.taverna.t2.workflowmodel.processor.config.ConfigurationBean;
import net.sf.taverna.t2.workflowmodel.processor.config.ConfigurationProperty;

/**
 * <p>
 * Defines a configuration type that relates directly to an {@link Activity} and
 * in particular defines details its input and output ports.<br>
 * An Activity that has its ports implicitly defined may define a ConfigType
 * that extends this class, but this is not enforced.
 * </p>
 * 
 * @author Stuart Owen
 */
@ConfigurationBean(uri = "http://ns.taverna.org.uk/2010/scufl2#ActivityPortsDefinition")
public class ActivityPortsDefinitionBean {
	private List<ActivityInputPortDefinitionBean> inputs = new ArrayList<>();
	private List<ActivityOutputPortDefinitionBean> outputs = new ArrayList<>();

	/**
	 * @return a list of {@link ActivityInputPortDefinitionBean} that describes
	 *         each input port
	 */
	public List<ActivityInputPortDefinitionBean> getInputPortDefinitions() {
		return inputs;
	}

	/**
	 * @return a list of {@link ActivityOutputPortDefinitionBean} that describes
	 *         each output port.
	 */
	public List<ActivityOutputPortDefinitionBean> getOutputPortDefinitions() {
		return outputs;
	}

	/**
	 * @param portDefinitions
	 *            a list of {@link ActivityInputPortDefinitionBean} that
	 *            describes each input port
	 */
	@ConfigurationProperty(name = "inputPortDefinition", label = "Input Ports", description = "", required = false, ordering = ConfigurationProperty.OrderPolicy.NON_ORDERED)
	public void setInputPortDefinitions(
			List<ActivityInputPortDefinitionBean> portDefinitions) {
		inputs = portDefinitions;
	}

	/**
	 * @param portDefinitions
	 *            a list of {@link ActivityOutputPortDefinitionBean} that
	 *            describes each output port
	 */
	@ConfigurationProperty(name = "outputPortDefinition", label = "Output Ports", description = "", required = false, ordering = ConfigurationProperty.OrderPolicy.NON_ORDERED)
	public void setOutputPortDefinitions(
			List<ActivityOutputPortDefinitionBean> portDefinitions) {
		outputs = portDefinitions;
	}
}
