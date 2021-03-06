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
package net.sf.taverna.t2.reference;

import java.io.InputStream;

/**
 * SPI for objects that can render a POJO from an InputStream
 * 
 * @author Tom Oinn
 */
public interface StreamToValueConverterSPI<T> {
	/**
	 * The class of objects which this builder can construct from a stream
	 */
	Class<T> getPojoClass();

	/**
	 * Render the stream to the target object type
	 * 
	 * @param stream
	 *            input stream of data to render to the object; the caller will
	 *            close it
	 * @param charset
	 * @param dataNature
	 * @return the newly created object
	 */
	T renderFrom(InputStream stream, ReferencedDataNature dataNature,
			String charset);
}
