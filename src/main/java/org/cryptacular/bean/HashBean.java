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

/**
 * Strategy interface to support beans that produce hash outputs in various formats, e.g. raw bytes, hex output, etc.
 *
 * @author Marvin S. Addison
 * @param  <T>  Type of output (e.g. byte[], string) produced by hash bean.
 */
public interface HashBean<T>
{
  /**
   * Hashes the given data.
   *
   * @param  input  Data to hash.
   *
   * @return  Raw digest output.
   */
  T hash(byte[] input);


  /**
   * Hashes the given data.
   *
   * @param  input  Data to hash.
   *
   * @return  Raw digest output.
   */
  T hash(InputStream input);


  /**
   * Compares the hash of the input against a known hash output.
   *
   * @param  input  Data to hash.
   * @param  hash  Known hash against which to compare.
   *
   * @return  True if hash of input under digest is equal to given hash, false otherwise.
   */
  boolean compare(byte[] input, T hash);


  /**
   * Compares the hash of the input against a known hash output.
   *
   * @param  input  Stream containing data to hash.
   * @param  hash  Known hash against which to compare.
   *
   * @return  True if hash of input under digest is equal to given hash, false otherwise.
   */
  boolean compare(InputStream input, T hash);
}