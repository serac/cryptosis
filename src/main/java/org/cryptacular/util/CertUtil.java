/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.cryptacular.util;

import java.io.File;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.cryptacular.x509.ExtensionReader;
import org.cryptacular.x509.GeneralNameType;
import org.cryptacular.x509.KeyUsageBits;
import org.cryptacular.x509.dn.AttributeType;
import org.cryptacular.x509.dn.NameReader;

/**
 * Utility class providing convenience methods for common operations on X.509 certificates.
 *
 * @author  Middleware Services
 */
public final class CertUtil
{
  /** Private constructor of utility class. */
  private CertUtil() {}


  /**
   * Gets the common name attribute (CN) of the certificate subject distinguished name.
   *
   * @param  cert  Certificate to examine.
   *
   * @return  Subject CN or null if no CN attribute is defined in the subject DN.
   */
  public static String subjectCN(final X509Certificate cert)
  {
    return new NameReader(cert).readSubject().getValue(AttributeType.CommonName);
  }


  /**
   * Gets all subject alternative names defined on the given certificate.
   *
   * @param  cert  X.509 certificate to examine.
   *
   * @return  List of subject alternative names or null if no subject alt names are defined.
   */
  public static GeneralNames subjectAltNames(final X509Certificate cert)
  {
    return new ExtensionReader(cert).readSubjectAlternativeName();
  }


  /**
   * Gets all subject alternative names of the given type(s) on the given cert.
   *
   * @param  cert  X.509 certificate to examine.
   * @param  types  One or more subject alternative name types to fetch.
   *
   * @return  List of subject alternative names of the matching type(s) or null if none found.
   */
  public static GeneralNames subjectAltNames(final X509Certificate cert, final GeneralNameType... types)
  {
    final GeneralNamesBuilder builder = new GeneralNamesBuilder();
    for (GeneralName name : subjectAltNames(cert).getNames()) {
      for (GeneralNameType type : types) {
        if (type.ordinal() == name.getTagNo()) {
          builder.addName(name);
        }
      }
    }
    final GeneralNames names = builder.build();
    if (names.getNames().length == 0) {
      return null;
    }
    return names;
  }


  /**
   * Gets a list of all subject names defined for the given certificate. The list includes the first common name (CN)
   * specified in the subject distinguished name (if defined) and all subject alternative names.
   *
   * @param  cert  X.509 certificate to examine.
   *
   * @return  List of subject names.
   */
  public static List<String> subjectNames(final X509Certificate cert)
  {
    final List<String> names = new ArrayList<String>();
    final String cn = subjectCN(cert);
    if (cn != null) {
      names.add(cn);
    }
    final GeneralNames altNames = subjectAltNames(cert);
    if (altNames == null) {
      return names;
    }
    for (GeneralName name : altNames.getNames()) {
      names.add(name.getName().toString());
    }
    return names;
  }


  /**
   * Gets a list of subject names defined for the given certificate. The list includes the first common name (CN)
   * specified in the subject distinguished name (if defined) and all subject alternative names of the given type.
   *
   * @param  cert  X.509 certificate to examine.
   * @param  types  One or more subject alternative name types to fetch.
   *
   * @return  List of subject names.
   */
  public static List<String> subjectNames(final X509Certificate cert, final GeneralNameType... types)
  {
    final List<String> names = new ArrayList<String>();
    final String cn = subjectCN(cert);
    if (cn != null) {
      names.add(cn);
    }
    final GeneralNames altNames = subjectAltNames(cert, types);
    if (altNames == null) {
      return names;
    }
    for (GeneralName name : altNames.getNames()) {
      names.add(name.getName().toString());
    }
    return names;
  }


  /**
   * Finds a certificate whose public key is paired with the given private key.
   *
   * @param  key  Private key used to find matching public key.
   * @param  candidates  Array of candidate certificates.
   *
   * @return  Certificate whose public key forms a keypair with the private key or null if no match is found.
   */
  public static X509Certificate findEntityCertificate(final PrivateKey key, final X509Certificate... candidates)
  {
    return findEntityCertificate(key, Arrays.asList(candidates));
  }


  /**
   * Finds a certificate whose public key is paired with the given private key.
   *
   * @param  key  Private key used to find matching public key.
   * @param  candidates  Collection of candidate certificates.
   *
   * @return  Certificate whose public key forms a keypair with the private key or null if no match is found.
   */
  public static X509Certificate findEntityCertificate(
    final PrivateKey key, final Collection<X509Certificate> candidates)
  {
    for (X509Certificate candidate : candidates) {
      if (KeyPairUtil.isKeyPair(candidate.getPublicKey(), key)) {
        return candidate;
      }
    }
    return null;
  }


  /**
   * Reads an X.509 certificate from ASN.1 encoded format in the file at the given location.
   *
   * @param  path  Path to file containing an DER or PEM encoded X.509 certificate.
   *
   * @return  Certificate.
   */
  public static X509Certificate readCertificate(final String path)
  {
    return readCertificate(StreamUtil.makeStream(new File(path)));
  }


  /**
   * Reads an X.509 certificate from ASN.1 encoded format from the given file.
   *
   * @param  file  File containing an DER or PEM encoded X.509 certificate.
   *
   * @return  Certificate.
   */
  public static X509Certificate readCertificate(final File file)
  {
    return readCertificate(StreamUtil.makeStream(file));
  }


  /**
   * Reads an X.509 certificate from ASN.1 encoded data in the given stream.
   *
   * @param  in  Input stream containing PEM or DER encoded X.509 certificate.
   *
   * @return  Certificate.
   */
  public static X509Certificate readCertificate(final InputStream in)
  {
    try {
      final CertificateFactory factory = CertificateFactory.getInstance("X.509");
      return (X509Certificate) factory.generateCertificate(in);
    } catch (CertificateException e) {
      throw new IllegalArgumentException("Error reading certificate", e);
    }
  }


  /**
   * Determines whether the certificate allows the given basic key usages.
   *
   * @param  cert  Certificate to check.
   * @param  bits  One or more basic key usage types to check.
   *
   * @return  True if certificate allows all given usage types, false otherwise.
   */
  public static boolean allowsUsage(final X509Certificate cert, final KeyUsageBits... bits)
  {
    final KeyUsage usage = new ExtensionReader(cert).readKeyUsage();
    for (KeyUsageBits bit : bits) {
      if (!bit.isSet(usage)) {
        return false;
      }
    }
    return true;
  }


  /**
   * Determines whether the certificate allows the given extended key usages.
   *
   * @param  cert  Certificate to check.
   * @param  purposes  One ore more extended key usage purposes to check.
   *
   * @return  True if certificate allows all given purposes, false otherwise.
   */
  public static boolean allowsUsage(final X509Certificate cert, final KeyPurposeId... purposes)
  {
    final List<KeyPurposeId> allowedUses = new ExtensionReader(cert).readExtendedKeyUsage();
    for (KeyPurposeId purpose : purposes) {
      if (!allowedUses.contains(purpose)) {
        return false;
      }
    }
    return true;
  }


  /**
   * Determines whether the certificate defines all of the given certificate policies.
   *
   * @param  cert  Certificate to check.
   * @param  policyOidsToCheck  One or more certificate policy OIDs to check.
   *
   * @return  True if certificate defines all given policy OIDs, false otherwise.
   */
  public static boolean hasPolicies(final X509Certificate cert, final String... policyOidsToCheck)
  {
    final List<PolicyInformation> policies = new ExtensionReader(cert).readCertificatePolicies();
    boolean hasPolicy;
    for (String policyOid : policyOidsToCheck) {
      hasPolicy = false;
      for (PolicyInformation policy : policies) {
        if (policy.getPolicyIdentifier().getId().equals(policyOid)) {
          hasPolicy = true;
          break;
        }
      }
      if (!hasPolicy) {
        return false;
      }
    }
    return true;
  }


  /**
   * Gets the subject key identifier of the given certificate in delimited hexadecimal format, e.g.
   * <code>25:48:2f:28:ec:5d:19:bb:1d:25:ae:94:93:b1:7b:b5:35:96:24:66</code>.
   *
   * @param  cert  Certificate to process.
   *
   * @return  Subject key identifier in colon-delimited hex format.
   */
  public static String subjectKeyId(final X509Certificate cert)
  {
    return CodecUtil.hex(new ExtensionReader(cert).readSubjectKeyIdentifier().getKeyIdentifier(), true);
  }


  /**
   * Gets the authority key identifier of the given certificate in delimited hexadecimal format, e.g.
   * <code>25:48:2f:28:ec:5d:19:bb:1d:25:ae:94:93:b1:7b:b5:35:96:24:66</code>.
   *
   * @param  cert  Certificate to process.
   *
   * @return  Authority key identifier in colon-delimited hex format.
   */
  public static String authorityKeyId(final X509Certificate cert)
  {
    return CodecUtil.hex(new ExtensionReader(cert).readAuthorityKeyIdentifier().getKeyIdentifier(), true);
  }
}
