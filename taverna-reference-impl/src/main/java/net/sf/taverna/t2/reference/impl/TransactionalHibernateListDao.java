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
package net.sf.taverna.t2.reference.impl;

import static net.sf.taverna.t2.reference.T2ReferenceType.IdentifiedList;

import java.util.List;

import net.sf.taverna.t2.reference.DaoException;
import net.sf.taverna.t2.reference.IdentifiedList;
import net.sf.taverna.t2.reference.ListDao;
import net.sf.taverna.t2.reference.T2Reference;
import net.sf.taverna.t2.reference.annotations.DeleteIdentifiedOperation;
import net.sf.taverna.t2.reference.annotations.GetIdentifiedOperation;
import net.sf.taverna.t2.reference.annotations.PutIdentifiedOperation;

import org.hibernate.Query;
import org.hibernate.SessionFactory;

/**
 * An implementation of ListDao based on based on raw hibernate session factory
 * injection and running within a spring managed context through auto-proxy
 * generation. To use this in spring inject a property 'sessionFactory' with
 * either a {@link org.springframework.orm.hibernate3.LocalSessionFactoryBean
 * LocalSessionFactoryBean} or the equivalent class from the T2Platform module
 * to add SPI based implementation discovery and mapping. To use outside of
 * Spring ensure you call the setSessionFactory(..) method before using this
 * (but really, use it from Spring, so much easier).
 * <p>
 * Methods in this Dao require transactional support
 * 
 * @author Tom Oinn
 */
public class TransactionalHibernateListDao implements ListDao {
	private static final String GET_REFLISTS_FOR_RUN = "FROM T2ReferenceListImpl WHERE namespacePart = :workflow_run_id";
	private SessionFactory sessionFactory;

	public void setSessionFactory(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	/**
	 * Fetch a t2reference list by id
	 * 
	 * @param ref
	 *            the T2Reference to fetch
	 * @return a retrieved identified list of T2 references
	 * @throws DaoException
	 *             if the supplied reference is of the wrong type or if
	 *             something goes wrong fetching the data or connecting to the
	 *             database
	 */
	@Override
	@GetIdentifiedOperation
	public IdentifiedList<T2Reference> get(T2Reference ref) throws DaoException {
		if (ref == null)
			throw new DaoException(
					"Supplied reference is null, can't retrieve.");
		if (!ref.getReferenceType().equals(IdentifiedList))
			throw new DaoException(
					"This dao can only retrieve reference of type T2Reference.IdentifiedList");
		if (!(ref instanceof T2ReferenceImpl))
			throw new DaoException(
					"Reference must be an instance of T2ReferenceImpl");

		try {
			return (T2ReferenceListImpl) sessionFactory.getCurrentSession()
					.get(T2ReferenceListImpl.class,
							((T2ReferenceImpl) ref).getCompactForm());
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	@Override
	@PutIdentifiedOperation
	public void store(IdentifiedList<T2Reference> theList) throws DaoException {
		if (theList.getId() == null)
			throw new DaoException("Supplied list set has a null ID, allocate "
					+ "an ID before calling the store method in the dao.");
		if (!theList.getId().getReferenceType().equals(IdentifiedList))
			throw new DaoException("Strangely the list ID doesn't have type "
					+ "T2ReferenceType.IdentifiedList, something has probably "
					+ "gone badly wrong somewhere earlier!");
		if (!(theList instanceof T2ReferenceListImpl))
			throw new DaoException(
					"Supplied identifier list not an instance of T2ReferenceList");

		try {
			sessionFactory.getCurrentSession().save(theList);
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	@Override
	public boolean delete(IdentifiedList<T2Reference> theList)
			throws DaoException {
		if (theList.getId() == null)
			throw new DaoException("Supplied list set has a null ID, allocate "
					+ "an ID before calling the store method in the dao.");
		if (!theList.getId().getReferenceType().equals(IdentifiedList))
			throw new DaoException("Strangely the list ID doesn't have type "
					+ "T2ReferenceType.IdentifiedList, something has probably "
					+ "gone badly wrong somewhere earlier!");
		if (!(theList instanceof T2ReferenceListImpl))
			throw new DaoException(
					"Supplied identifier list not an instance of T2ReferenceList");

		try {
			sessionFactory.getCurrentSession().delete(theList);
			return true;
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	@DeleteIdentifiedOperation
	public synchronized void deleteIdentifiedListsForWFRun(String workflowRunId)
			throws DaoException {
		try {
			// Select all T2Reference lists for this wf run
			Query selectQuery = sessionFactory.getCurrentSession().createQuery(
					GET_REFLISTS_FOR_RUN);
			selectQuery.setString("workflow_run_id", workflowRunId);
			List<IdentifiedList<T2Reference>> referenceLists = selectQuery
					.list();
			for (IdentifiedList<T2Reference> referenceList : referenceLists)
				delete(referenceList);
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}
}
