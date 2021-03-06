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

import net.sf.taverna.t2.workflowmodel.Configurable;
import net.sf.taverna.t2.workflowmodel.ConfigurationException;
import net.sf.taverna.t2.workflowmodel.EditException;

import org.apache.log4j.Logger;

/**
 * An Edit that is responsible for configuring a {@link Configurable} with a
 * given configuration bean.
 * 
 * @author Stuart Owen
 * @author Stian Soiland-Reyes
 * @author Donal Fellows
 */
class ConfigureEdit<T> extends EditSupport<Configurable<T>> {
	private static Logger logger = Logger.getLogger(ConfigureEdit.class);

	private final Configurable<T> configurable;
	private final Class<? extends Configurable<T>> configurableType;
	private final T configurationBean;

	ConfigureEdit(Class<? extends Configurable<T>> subjectType,
			Configurable<T> configurable, T configurationBean) {
		if (configurable == null)
			throw new RuntimeException(
					"Cannot construct an edit with null subject");
		this.configurableType = subjectType;
		this.configurable = configurable;
		this.configurationBean = configurationBean;
		if (!configurableType.isInstance(configurable))
			throw new RuntimeException(
					"Edit cannot be applied to an object which isn't an instance of "
							+ configurableType);
	}

	@Override
	public final Configurable<T> applyEdit() throws EditException {
		try {
			// FIXME: Should clone bean on configuration to prevent caller from
			// modifying bean afterwards
			synchronized (configurable) {
				configurable.configure(configurationBean);
			}
			return configurable;
		} catch (ConfigurationException e) {
			logger.error("Error configuring :"
					+ configurable.getClass().getSimpleName(), e);
			throw new EditException(e);
		}
	}

	@Override
	public final Configurable<T> getSubject() {
		return configurable;
	}
}
