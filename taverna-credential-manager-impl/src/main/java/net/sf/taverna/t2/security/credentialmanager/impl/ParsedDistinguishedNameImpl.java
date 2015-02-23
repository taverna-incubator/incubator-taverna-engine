/*******************************************************************************
 * Copyright (C) 2014 The University of Manchester
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
package net.sf.taverna.t2.security.credentialmanager.impl;

import java.net.URI;
import java.util.ArrayList;

import net.sf.taverna.t2.security.credentialmanager.ParsedDistinguishedName;

import org.apache.log4j.Logger;

/**
 * Parses a Distinguished Name and stores the parts for retrieval.
 * <p>
 * From RFC 2253:
 * <ul>
 * <li><b>CN</b>: commonName
 * <li><b>L</b>: localityName
 * <li><b>ST</b>: stateOrProvinceName
 * <li><b>O</b>: organizationName
 * <li><b>OU</b>: organizationalUnitName
 * <li><b>C</b>: countryName
 * <li><b>STREET</b>: streetAddress <i>(ignored)</i>
 * <li><b>DC</b>: domainComponent <i>(ignored)</i>
 * <li><b>UID</b>: userid <i>(ignored)</i>
 * </ul>
 * 
 * @author Alex Nenadic
 * @author Stian Soiland-Reyes
 * @author Christian Brenninkmeijer
 */
@SuppressWarnings("unused")
public class ParsedDistinguishedNameImpl implements ParsedDistinguishedName {
	private static final char SEPARATOR_CHARACTER = ',';
	private static final char ESCAPE_CHARACTER = '\\';
	private static final char QUOTE_CHARACTER = '\"';
	private static final String KEY_VALUE_SEPARATOR = "=";

	private static final Logger logger = Logger.getLogger(ParsedDistinguishedNameImpl.class);

	/** not from RFC 2253, yet some certificates contain this field */
	private String emailAddress = "none";
	/** common name */
	private String CN = "none";
	/** locality */
	private String L = "none";
	/** state or province */
	private String ST = "none";
	/** country */
	private String C = "none";
	/** organisation */
	private String O = "none";
	/** organisation unit (department, faculty, etc.) */
	private String OU = "none";

	// /**
	// * Gets the intended certificate uses, i.e. Netscape Certificate Type
	// * extension (2.16.840.1.113730.1.1) as a string.
	// */
	// // From openssl's documentation: "The [above] extension is non standard,
	// Netscape
	// // specific and largely obsolete. Their use in new applications is
	// discouraged."
	// // TODO replace with "basicConstraints, keyUsage and extended key usage
	// extensions
	// // which are now used instead."
	// public static String getIntendedCertificateUses(byte[] value) {
	//
	// // Netscape Certificate Types (2.16.840.1.113730.1.1) denoting the
	// // intended uses of a certificate
	// int[] INTENDED_USES = new int[] { NetscapeCertType.sslClient,
	// NetscapeCertType.sslServer, NetscapeCertType.smime,
	// NetscapeCertType.objectSigning, NetscapeCertType.reserved,
	// NetscapeCertType.sslCA, NetscapeCertType.smimeCA,
	// NetscapeCertType.objectSigningCA, };
	//
	// // Netscape Certificate Type strings (2.16.840.1.113730.1.1)
	// HashMap<String, String> INTENDED_USES_STRINGS = new HashMap<String,
	// String>();
	// INTENDED_USES_STRINGS.put("128", "SSL Client");
	// INTENDED_USES_STRINGS.put("64", "SSL Server");
	// INTENDED_USES_STRINGS.put("32", "S/MIME");
	// INTENDED_USES_STRINGS.put("16", "Object Signing");
	// INTENDED_USES_STRINGS.put("8", "Reserved");
	// INTENDED_USES_STRINGS.put("4", "SSL CA");
	// INTENDED_USES_STRINGS.put("2", "S/MIME CA");
	// INTENDED_USES_STRINGS.put("1", "Object Signing CA");
	//
	// // Get DER octet string from extension value
	// ASN1OctetString derOctetString = new DEROctetString(value);
	// byte[] octets = derOctetString.getOctets();
	// // Get DER bit string
	// DERBitString derBitString = new DERBitString(octets);
	// int val = new NetscapeCertType(derBitString).intValue();
	// StringBuffer strBuff = new StringBuffer();
	// for (int i = 0, len = INTENDED_USES.length; i < len; i++) {
	// int use = INTENDED_USES[i];
	// if ((val & use) == use) {
	// strBuff.append(INTENDED_USES_STRINGS.get(String.valueOf(use))
	// + ", \n");
	// }
	// }
	// // remove the last ", \n" from the end of the buffer
	// String str = strBuff.toString();
	// str = str.substring(0, str.length() - 3);
	// return str;
	// }

	/**
	 * Parses a DN string and fills in fields with DN parts. Heavily based on
	 * uk.ac.omii.security.utils.DNParser class from omii-security-utils
	 * library.
	 * 
	 * @see http://maven.omii.ac.uk/maven2/repository/omii/omii-security-utils/
	 */
	public ParsedDistinguishedNameImpl(String DNstr) {
		/*
		 * Parse the DN String and put into variables. First, tokenise using a
		 * "," character as a delimiter UNLESS escaped with a "\" character. Put
		 * the tokens into an ArrayList. These should be name value pairs
		 * separated by "=". Tokenise these using a StringTokenizer class, test
		 * for the name, and if one of the recognised names, copy into the
		 * correct variable. The reason StringTokenizer is not used for the
		 * major token list is that the StringTokenizer class does not handle
		 * escaped delimiters so an escaped delimiter in the code would be
		 * treated as a valid one.
		 */

		for (String currentToken : tokenize(DNstr)) {
			// split on first equals only, as value can contain an equals char
			String[] minorTokens = currentToken.trim().split(KEY_VALUE_SEPARATOR, 2);

			/*
			 * there had better be a key and a value only, else we have a key
			 * with no value, so skip processing the key.
			 */
			if (minorTokens.length != 2)
				continue;
			switch (minorTokens[0].toUpperCase()) {
			case "CN":
			case "COMMONNAME":
				CN = minorTokens[1];
				break;
			case "EMAIL":
			case "EMAILADDRESS":
				emailAddress = minorTokens[1];
				break;
			case "OU":
			case "ORGANIZATIONALUNITNAME":
				OU = minorTokens[1];
				break;
			case "O":
			case "ORGANIZATIONNAME":
				O = minorTokens[1];
				break;
			case "L":
			case "LOCALITYNAME":
				L = minorTokens[1];
				break;
			case "ST":
			case "STATEORPROVINCENAME":
				ST = minorTokens[1];
				break;
			case "C":
			case "COUNTRYNAME":
				C = minorTokens[1];
				break;
			}
		}
	}

	private ArrayList<String> tokenize(String DNstr) {
		int startIndex = 0;
		int endIndex = 0;
		boolean ignoreThisChar = false;
		boolean inQuotes = false;

		ArrayList<String> majorTokenList = new ArrayList<>();

		for (int i = 0; i < DNstr.length(); i++) {
			char ch = DNstr.charAt(i);
			if (ignoreThisChar == true)
				ignoreThisChar = false;
			else if (ch == QUOTE_CHARACTER)
				inQuotes = !inQuotes;
			else if (inQuotes)
				continue;
			else if (ch == ESCAPE_CHARACTER)
				ignoreThisChar = true;
			else if (ch == SEPARATOR_CHARACTER && !ignoreThisChar) {
				endIndex = i;
				majorTokenList.add(DNstr.substring(startIndex, endIndex));
				startIndex = i + 1;
			}
		}

		// Add last token - after the last delimiter
		majorTokenList.add(DNstr.substring(startIndex, DNstr.length()));
		return majorTokenList;
	}

	@Override
	public String getCN() {
		return CN;
	}

	@Override
	public String getEmailAddress() {
		return emailAddress;
	}

	@Override
	public String getOU() {
		return OU;
	}

	@Override
	public String getO() {
		return O;
	}

	@Override
	public String getL() {
		return L;
	}

	@Override
	public String getST() {
		return ST;
	}

	@Override
	public String getC() {
		return C;
	}
}
