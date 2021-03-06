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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link HashUtil}.
 *
 * @author Marvin S. Addison
 */
public class HashUtilTest
{
  private static final byte[] SALT = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};

  @DataProvider(name = "salted-hash-iter")
  public Object[][] getSaltedHashData()
  {
    return new Object[][] {
      new Object[] {
        new SHA1Digest(),
        "deoxyribonucleic acid",
        null,
        1,
        "d1a0cce60feaa9f555ffc308aa44ca41a9255928",
      },
      new Object[] {
        new SHA1Digest(),
        "protoporphyrin-9",
        SALT,
        1,
        "98d8f48fbfa0d6923ba29b99a12591aba0b452380001020304050607",
      },
      new Object[] {
        new SHA256Digest(),
        "N-arachidonoylethanolamine",
        SALT,
        5,
        "456220dc121776a64f23d0bb3c5bd29fada6894dcbf69a275592ef2a60bd5e540001020304050607",
      },
    };
  }


  @DataProvider(name = "file-hashes")
  public Object[][] getFileHashes()
  {
    return new Object[][] {
      new Object[] {
        "src/test/resources/plaintexts/lorem-1200.txt",
        "f0746e8978b3eccca05284dd12f098fdea32c8bc",
      },
      new Object[] {
        "src/test/resources/plaintexts/lorem-5000.txt",
        "1142d7a2661760624fa41b002be6c66c23b50602",
      },
    };
  }


  @Test(dataProvider = "salted-hash-iter")
  public void testSaltedHashIter(
    final Digest digest, final String data, final byte[] salt, final int iterations, final String expected)
    throws Exception
  {
    assertEquals(Hex.toHexString(HashUtil.hash(digest, data.getBytes("ASCII"), salt, iterations)), expected);
  }


  @Test(dataProvider = "salted-hash-iter")
  public void testCompareSaltedHash(
    final Digest digest, final String data, final byte[] salt, final int iterations, final String expected)
    throws Exception
  {
    assertTrue(HashUtil.compareSaltedHash(digest, data.getBytes("ASCII"), iterations, CodecUtil.hex(expected)));
  }


  @Test(dataProvider = "file-hashes")
  public void testHashStream(final String path, final String expected) throws Exception
  {
    final InputStream in = StreamUtil.makeStream(new File(path));
    try {
      assertEquals(Hex.toHexString(HashUtil.sha1(in)), expected);
    } finally {
      in.close();
    }
  }
}
