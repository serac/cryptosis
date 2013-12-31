package org.cryptosis.bean;

import org.cryptosis.CiphertextHeader;
import org.cryptosis.generator.Nonce;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;

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


  /** {@inheritDoc} */
  @Override
  public byte[] encrypt(final byte[] input)
  {
    return process(new CiphertextHeader(nonce.generate(), keyAlias), lookupKey(keyAlias), true, input);
  }


  /** {@inheritDoc} */
  @Override
  public void encrypt(InputStream input, OutputStream output)
  {
    process(new CiphertextHeader(nonce.generate(), keyAlias), lookupKey(keyAlias), true, input, output);
  }


  /** {@inheritDoc} */
  @Override
  public byte[] decrypt(byte[] input)
  {
    final CiphertextHeader header = CiphertextHeader.decode(input);
    return process(header, lookupKey(header.getKeyName()), false, input);
  }


  /** {@inheritDoc} */
  @Override
  public void decrypt(InputStream input, OutputStream output)
  {
    final CiphertextHeader header = CiphertextHeader.decode(input);
    process(header, lookupKey(header.getKeyName()), false, input, output);
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
   * @param  secretKey  Symmetric encryption key.
   * @param  encryptionMode  True for encryption; false for decryption.
   * @param  input  Data to process by cipher.
   *
   * @return  Ciphertext data under encryption, plaintext data under decryption.
   */
  protected abstract byte[] process(CiphertextHeader header, SecretKey secretKey, boolean encryptionMode, byte[] input);


  /**
   * Processes the given data under the action of the cipher.
   *
   * @param  header  Ciphertext header.
   * @param  secretKey  Symmetric encryption key.
   * @param  encryptionMode  True for encryption; false for decryption.
   * @param  input  Stream containing input data.
   * @param  output  Stream that receives output of cipher.
   */
  protected abstract void process(
      CiphertextHeader header, SecretKey secretKey, boolean b, InputStream input, OutputStream output);
}
