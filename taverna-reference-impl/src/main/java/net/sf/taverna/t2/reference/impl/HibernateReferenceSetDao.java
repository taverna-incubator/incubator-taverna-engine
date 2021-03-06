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

import static net.sf.taverna.t2.reference.T2ReferenceType.ReferenceSet;

import java.util.List;

import net.sf.taverna.t2.reference.DaoException;
import net.sf.taverna.t2.reference.ReferenceSet;
import net.sf.taverna.t2.reference.ReferenceSetDao;
import net.sf.taverna.t2.reference.T2Reference;
import net.sf.taverna.t2.reference.annotations.DeleteIdentifiedOperation;
import net.sf.taverna.t2.reference.annotations.GetIdentifiedOperation;
import net.sf.taverna.t2.reference.annotations.PutIdentifiedOperation;

import org.hibernate.Query;
import org.hibernate.Session;
import org.springframework.orm.hibernate3.support.HibernateDaoSupport;

/**
 * An implementation of ReferenceSetDao based on Spring's HibernateDaoSupport.
 * To use this in spring inject a property 'sessionFactory' with either a
 * {@link org.springframework.orm.hibernate3.LocalSessionFactoryBean
 * LocalSessionFactoryBean} or the equivalent class from the T2Platform module
 * to add SPI based implementation discovery and mapping. To use outside of
 * Spring ensure you call the setSessionFactory(..) method before using this
 * (but really, use it from Spring, so much easier).
 * 
 * @author Tom Oinn
 */
public class HibernateReferenceSetDao extends HibernateDaoSupport implements
		ReferenceSetDao {
	private static final String GET_REFSETS_FOR_RUN = "FROM ReferenceSetImpl WHERE namespacePart = :workflow_run_id";

	/**
	 * Store the specified new reference set
	 * 
	 * @param rs
	 *            a reference set, must not already exist in the database.
	 * @throws DaoException
	 *             if the entry already exists in the database, if the supplied
	 *             reference set isn't an instance of ReferenceSetImpl or if
	 *             something else goes wrong connecting to the database
	 */
	@Override
	@PutIdentifiedOperation
	public void store(ReferenceSet rs) throws DaoException {
		if (rs.getId() == null)
			throw new DaoException(
					"Supplied reference set has a null ID, allocate "
							+ "an ID before calling the store method in the dao.");
		if (!rs.getId().getReferenceType().equals(ReferenceSet))
			throw new DaoException(
					"Strangely the reference set ID doesn't have type "
							+ "T2ReferenceType.ReferenceSet, something has probably "
							+ "gone badly wrong somewhere earlier!");
		if (!(rs instanceof ReferenceSetImpl))
			throw new DaoException(
					"Supplied reference set not an instance of ReferenceSetImpl");

		try {
			getHibernateTemplate().save(rs);
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	/**
	 * Update a pre-existing entry in the database
	 * 
	 * @param rs
	 *            the reference set to update. This must already exist in the
	 *            database
	 * @throws DaoException
	 */
	@Override
	@PutIdentifiedOperation
	public void update(ReferenceSet rs) throws DaoException {
		if (rs.getId() == null)
			throw new DaoException(
					"Supplied reference set has a null ID, allocate "
							+ "an ID before calling the store method in the dao.");
		if (!rs.getId().getReferenceType().equals(ReferenceSet))
			throw new DaoException(
					"Strangely the reference set ID doesn't have type "
							+ "T2ReferenceType.ReferenceSet, something has probably "
							+ "gone badly wrong somewhere earlier!");
		if (!(rs instanceof ReferenceSetImpl))
			throw new DaoException(
					"Supplied reference set not an instance of ReferenceSetImpl");

		try {
			getHibernateTemplate().update(rs);
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	/**
	 * Fetch a reference set by id
	 * 
	 * @param ref
	 *            the ReferenceSetT2ReferenceImpl to fetch
	 * @return a retrieved ReferenceSetImpl
	 * @throws DaoException
	 *             if the supplied reference is of the wrong type or if
	 *             something goes wrong fetching the data or connecting to the
	 *             database
	 */
	@Override
	@GetIdentifiedOperation
	public ReferenceSetImpl get(T2Reference ref) throws DaoException {
		if (ref == null)
			throw new DaoException(
					"Supplied reference is null, can't retrieve.");
		if (!ref.getReferenceType().equals(ReferenceSet))
			throw new DaoException(
					"This dao can only retrieve reference of type T2Reference.ReferenceSet");
		if (!(ref instanceof T2ReferenceImpl))
			throw new DaoException(
					"Reference must be an instance of T2ReferenceImpl");

		try {
			return (ReferenceSetImpl) getHibernateTemplate().get(
					ReferenceSetImpl.class,
					((T2ReferenceImpl) ref).getCompactForm());
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	@Override
	@DeleteIdentifiedOperation
	public boolean delete(ReferenceSet rs) throws DaoException {
		if (rs.getId() == null)
			throw new DaoException(
					"Supplied reference set has a null ID, allocate "
							+ "an ID before calling the store method in the dao.");
		if (!rs.getId().getReferenceType().equals(ReferenceSet))
			throw new DaoException(
					"Strangely the reference set ID doesn't have type "
							+ "T2ReferenceType.ReferenceSet, something has probably "
							+ "gone badly wrong somewhere earlier!");
		if (!(rs instanceof ReferenceSetImpl))
			throw new DaoException(
					"Supplied reference set not an instance of ReferenceSetImpl");

		try {
			getHibernateTemplate().delete(rs);
			return true;
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	@DeleteIdentifiedOperation
	public synchronized void deleteReferenceSetsForWFRun(String workflowRunId)
			throws DaoException {
		try {
			// Select all ReferenceSets for this wf run
			Session session = getSession();
			Query selectQuery = session
					.createQuery(GET_REFSETS_FOR_RUN);
			selectQuery.setString("workflow_run_id", workflowRunId);
			List<ReferenceSet> referenceSets = selectQuery.list();
			session.close();
			/*
			 * need to close before we do delete otherwise hibernate complains
			 * that two sessions are accessing collection
			 */
			getHibernateTemplate().deleteAll(referenceSets);
		} catch (Exception ex) {
			throw new DaoException(ex);
		}
	}
}
