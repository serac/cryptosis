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

import org.cryptacular.CiphertextHeader;
import org.cryptacular.adapter.BlockCipherAdapter;
import org.cryptacular.io.ChunkHandler;
import org.cryptacular.util.StreamUtil;

/**
 * Base class for all cipher beans that use block cipher.
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractBlockCipherBean extends AbstractCipherBean
{
  /** {@inheritDoc} */
  @Override
  protected byte[] process(final CiphertextHeader header, final boolean mode, final byte[] input)
  {
    final BlockCipherAdapter cipher = newCipher(header, mode);
    final byte[] headerBytes = header.encode();
    int outOff;
    final int inOff;
    final int length;
    final byte[] output;
    if (mode) {
      final int outSize = headerBytes.length + cipher.getOutputSize(input.length);
      output = new byte[outSize];
      System.arraycopy(headerBytes, 0, output, 0, headerBytes.length);
      inOff = 0;
      outOff = headerBytes.length;
      length = input.length;
    } else {
      length = input.length - headerBytes.length;
      final int outSize = cipher.getOutputSize(length);
      output = new byte[outSize];
      inOff = headerBytes.length;
      outOff = 0;
    }
    outOff += cipher.processBytes(input, inOff, length, output, outOff);
    outOff += cipher.doFinal(output, outOff);
    if (outOff < output.length) {
      final byte[] copy = new byte[outOff];
      System.arraycopy(output, 0, copy, 0, outOff);
      return copy;
    }
    return output;
  }


  /** {@inheritDoc} */
  @Override
  protected void process(
    final CiphertextHeader header,
    final boolean mode,
    final InputStream input,
    final OutputStream output)
  {
    final BlockCipherAdapter cipher = newCipher(header, mode);
    final int outSize = cipher.getOutputSize(StreamUtil.CHUNK_SIZE);
    final byte[] outBuf = new byte[outSize > StreamUtil.CHUNK_SIZE ? outSize : StreamUtil.CHUNK_SIZE];
    StreamUtil.pipeAll(input, output, new ChunkHandler() {
      @Override
      public void handle(final byte[] input, final int offset, final int count, final OutputStream output)
        throws IOException
      {
        final int n = cipher.processBytes(input, offset, count, outBuf, 0);
        output.write(outBuf, 0, n);
      }
    });
    final int n = cipher.doFinal(outBuf, 0);
    try {
      output.write(outBuf, 0, n);
    } catch (IOException e) {
      throw new RuntimeException("IO error writing final output", e);
    }
  }


  /**
   * Creates a new cipher adapter instance suitable for the block cipher used by this class.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   *
   * @return  Block cipher adapter that wraps an initialized block cipher that is ready for use in the given mode.
   */
  protected abstract BlockCipherAdapter newCipher(CiphertextHeader header, boolean mode);
}
