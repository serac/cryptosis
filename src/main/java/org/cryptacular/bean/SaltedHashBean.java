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

import java.io.InputStream;

import org.cryptacular.generator.Nonce;
import org.cryptacular.util.HashUtil;

/**
 * Computes a salted hash from a random salt source.
 *
 * @author Marvin S. Addison
 */
public class SaltedHashBean extends EncodingHashBean
{
  /** Random salt source. */
  private Nonce saltSource;

  /** Number of hash iterations. */
  private int iterations = 1;


  /**
   * @return  Random salt source.
   */
  public Nonce getSaltSource()
  {
    return saltSource;
  }


  /**
   * Sets the random salt source.
   *
   * @param  saltSource  Source of random salt data.
   */
  public void setSaltSource(final Nonce saltSource)
  {
    this.saltSource = saltSource;
  }


  /**
   * @return  Number of iterations the digest function is applied to the input data.
   */
  public int getIterations()
  {
    return iterations;
  }


  /**
   * Sets the number of iterations the digest function is applied to the input data.
   *
   * @param  iterations  Digest function iterations. Default value is 1.
   */
  public void setIterations(final int iterations)
  {
    this.iterations = iterations;
  }


  /** {@inheritDoc} */
  @Override
  public boolean compare(final byte[] input, final String hash)
  {
    return HashUtil.compareSaltedHash(
      digestSpec.newInstance(),
      input,
      iterations,
      decode(hash));
  }


  /** {@inheritDoc} */
  @Override
  public boolean compare(final InputStream input, final String hash)
  {
    return HashUtil.compareSaltedHash(
      digestSpec.newInstance(),
      input,
      iterations,
      decode(hash));
  }


  /** {@inheritDoc} */
  @Override
  protected byte[] computeHash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input, saltSource.generate(), iterations);
  }
}
