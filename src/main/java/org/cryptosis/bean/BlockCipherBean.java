package org.cryptosis.bean;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.cryptosis.CiphertextHeader;
import org.cryptosis.spec.Spec;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Cipher bean that performs symmetric encryption/decryption using a standard block cipher in a standard mode (e.g.
 * CBC, OFB) with padding to support processing inputs of arbitrary length.
 *
 * @author Marvin S. Addison
 */
public class BlockCipherBean extends AbstractCipherBean
{
  /** Block cipher specification (algorithm, mode, padding). */
  private Spec<BufferedBlockCipher> blockCipherSpec;


  /** {@inheritDoc} */
  @Override
  protected byte[] process(
      final CiphertextHeader header, final SecretKey secretKey, final boolean encryptionMode, final byte[] input)
  {
    final BufferedBlockCipher cipher = newCipher(header, secretKey, encryptionMode);
    final byte[] headerBytes = header.encode();
    int outOff;
    final byte[] output;
    if (encryptionMode) {
      final int outSize = headerBytes.length + cipher.getOutputSize(input.length);
      output = new byte[outSize];
      System.arraycopy(headerBytes, 0, output, 0, headerBytes.length);
      outOff = headerBytes.length;
    } else {
      final int outSize = cipher.getOutputSize(input.length - headerBytes.length);
      output = new byte[outSize];
      outOff = 0;
    }
    outOff += cipher.processBytes(input, 0, input.length, output, outOff);
    try {
      cipher.doFinal(output, outOff);
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException("Cipher processing failed", e);
    }
    return output;
  }


  /** {@inheritDoc} */
  @Override
  protected void process(
      final CiphertextHeader header,
      final SecretKey secretKey,
      final boolean encryptionMode,
      final InputStream input,
      final OutputStream output)
  {
    final BufferedBlockCipher cipher = newCipher(header, secretKey, encryptionMode);
    final byte[] headerBytes = header.encode();
  }


  /**
   * Creates a new buffered block cipher initialized and ready for use in the indicated mode.
   *
   * @param  header  Ciphertext header.
   * @param  secretKey  Symmetric encryption key.
   * @param  encryptionMode  True for encryption; false for decryption.
   *
   * @return  Initialized cipher.
   */
  private BufferedBlockCipher newCipher(
      final CiphertextHeader header, final SecretKey secretKey, final boolean encryptionMode)
  {
    final BufferedBlockCipher cipher = blockCipherSpec.newInstance();
    final ParametersWithIV params = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), header.getNonce());
    cipher.init(encryptionMode, params);
    return cipher;
  }
}
