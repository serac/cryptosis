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

package org.cryptacular.pbe;

import org.cryptacular.spec.KeyedBlockCipherSpec;

/**
 * Describes block ciphers allowed with the OpenSSL password-based encryption scheme.
 *
 * @author Marvin S. Addison
 */
public enum OpenSSLAlgorithm
{
  /** AES-128 in CBC mode. */
  AES_128_CBC("aes-128-cbc", new KeyedBlockCipherSpec("AES", "CBC", "PKCS5", 128)),

  /** AES-192 in CBC mode. */
  AES_192_CBC("aes-192-cbc", new KeyedBlockCipherSpec("AES", "CBC", "PKCS5", 192)),

  /** AES-256 in CBC mode. */
  AES_256_CBC("aes-256-cbc", new KeyedBlockCipherSpec("AES", "CBC", "PKCS5", 256)),

  /** DES in CBC mode. */
  DES_CBC("des-cbc", new KeyedBlockCipherSpec("DES", "CBC", "PKCS5", 64)),

  /** Triple DES in CBC mode. */
  DES_EDE3_CBC("des-ede3-cbc", new KeyedBlockCipherSpec("DESede", "CBC", "PKCS5", 192)),

  /** 128-bit RC2 in CBC mode. */
  RC2_CBC("rc2-cbc", new KeyedBlockCipherSpec("RC2", "CBC", "PKCS5", 128)),

  /** 40-bit RC2 in CBC mode. */
  RC2_40_CBC("rc2-40-cbc", new KeyedBlockCipherSpec("RC2", "CBC", "PKCS5", 40)),

  /** 64-bit RC2 in CBC mode. */
  RC2_64_CBC("rc2-64-cbc", new KeyedBlockCipherSpec("RC2", "CBC", "PKCS5", 64));


  /** Algorithm identifier, e.g. aes-128-cbc. */
  private final String algorithmId;

  /** Cipher algorithm specification. */
  private final KeyedBlockCipherSpec cipherSpec;

  /**
   * Creates a new instance with given parameters.
   *
   * @param  algId  Algorithm identifier, e.g. aes-128-cbc.
   * @param  cipherSpec  Block cipher specification that corresponds to algorithm ID.
   */
  OpenSSLAlgorithm(final String algId, final KeyedBlockCipherSpec cipherSpec)
  {
    this.algorithmId = algId;
    this.cipherSpec = cipherSpec;
  }

  /** @return  OpenSSL algorithm identifier, e.g. aes-128-cbc. */
  public String getAlgorithmId()
  {
    return algorithmId;
  }

  /** @return  Cipher algorithm specification. */
  public KeyedBlockCipherSpec getCipherSpec()
  {
    return cipherSpec;
  }


  /**
   * Converts an OID to the corresponding algorithm specification.
   *
   * @param  algorithmId  Algorithm OID.
   *
   * @return  Algorithm spec.
   */
  public static OpenSSLAlgorithm fromAlgorithmId(final String algorithmId)
  {
    for (OpenSSLAlgorithm alg : values()) {
      if (alg.getAlgorithmId().equalsIgnoreCase(algorithmId)) {
        return alg;
      }
    }
    throw new IllegalArgumentException("Unsupported algorithm " + algorithmId);
  }
}
