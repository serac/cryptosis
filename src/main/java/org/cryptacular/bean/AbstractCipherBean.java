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

package org.cryptacular.bean;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.SecretKey;

import org.cryptacular.CiphertextHeader;
import org.cryptacular.generator.Nonce;

/**
 * Base class for all cipher beans. The base class assumes all ciphertext output will contain a prepended
 * {@link CiphertextHeader} containing metadata that facilitates decryption.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractCipherBean implements CipherBean
{
  /** Keystore containing symmetric key(s). */
  private KeyStore keyStore;

  /** Keystore entry for alias of current key. */
  private String keyAlias;

  /** Password on private key entry. */
  private String keyPassword;

  /** Nonce generator. */
  private Nonce nonce;


  /**
   * @return  Keystore that contains the {@link SecretKey}.
   */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /**
   * Sets the keystore containing encryption/decryption key(s). The keystore must contain a {@link SecretKey} entry
   * whose alias is given by {@link #setKeyAlias(String)}, which will be used at the encryption key. It may contain
   * additional symmetric keys to support, for example, key rollover where some existing ciphertexts have headers
   * specifying a different key. In general all keys used for outstanding ciphertexts should be contained in the
   * keystore.
   *
   * @param  keyStore  Keystore containing encryption key(s).
   */
  public void setKeyStore(final KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }


  /**
   * @return  Alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}.
   */
  public String getKeyAlias()
  {
    return keyAlias;
  }


  /**
   * Sets the keystore entry alias used to locate the current encryption key.
   *
   * @param  keyAlias  Alias of {@link SecretKey} used for encryption.
   */
  public void setKeyAlias(final String keyAlias)
  {
    this.keyAlias = keyAlias;
  }


  /**
   * Sets the password used to access the encryption key.
   *
   * @param  keyPassword  Encryption key password.
   */
  public void setKeyPassword(final String keyPassword)
  {
    this.keyPassword = keyPassword;
  }


  /**
   * @return  Nonce/IV generation strategy.
   */
  public Nonce getNonce()
  {
    return nonce;
  }


  /**
   * Sets the nonce/IV generation strategy.
   *
   * @param  nonce  Nonce generator.
   */
  public void setNonce(final Nonce nonce)
  {
    this.nonce = nonce;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] encrypt(final byte[] input)
  {
    return process(new CiphertextHeader(nonce.generate(), keyAlias), true, input);
  }


  /** {@inheritDoc} */
  @Override
  public void encrypt(final InputStream input, final OutputStream output)
  {
    final CiphertextHeader header = new CiphertextHeader(nonce.generate(), keyAlias);
    try {
      output.write(header.encode());
    } catch (IOException e) {
      throw new RuntimeException("Error writing ciphertext header to output stream", e);
    }
    process(header, true, input, output);
  }


  /** {@inheritDoc} */
  @Override
  public byte[] decrypt(final byte[] input)
  {
    final CiphertextHeader header = CiphertextHeader.decode(input);
    return process(header, false, input);
  }


  /** {@inheritDoc} */
  @Override
  public void decrypt(final InputStream input, final OutputStream output)
  {
    final CiphertextHeader header = CiphertextHeader.decode(input);
    process(header, false, input, output);
  }


  /**
   * Looks up secret key entry in the {@link #keyStore}.
   *
   * @param  alias  Name of secret key entry.
   *
   * @return  Secret key.
   */
  protected SecretKey lookupKey(final String alias)
  {
    final Key key;
    try {
      key = keyStore.getKey(alias, keyPassword.toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error accessing " + alias, e);
    }
    if (key instanceof SecretKey) {
      return (SecretKey) key;
    }
    throw new IllegalArgumentException(alias + " is not a secret key");
  }


  /**
   * Processes the given data under the action of the cipher.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   * @param  input  Data to process by cipher.
   *
   * @return  Ciphertext data under encryption, plaintext data under decryption.
   */
  protected abstract byte[] process(CiphertextHeader header, boolean mode, byte[] input);


  /**
   * Processes the given data under the action of the cipher.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   * @param  input  Stream containing input data.
   * @param  output  Stream that receives output of cipher.
   */
  protected abstract void process(CiphertextHeader header, boolean mode, InputStream input, OutputStream output);
}
