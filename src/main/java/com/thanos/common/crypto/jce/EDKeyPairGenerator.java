/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */
package com.thanos.common.crypto.jce;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

import java.security.*;

public final class EDKeyPairGenerator {

  public static final String ALGORITHM = "EdDSA";
  public static final String CURVE_NAME = EdDSAParameterSpec.Ed25519;

  private static final String algorithmAssertionMsg =
      "Assumed JRE supports ED25519 key pair generation";

  private static final String keySpecAssertionMsg =
      "Assumed correct key spec statically";

  private static final EdDSAParameterSpec ED25519_CURVE
      = new EdDSAParameterSpec(CURVE_NAME);

  private EDKeyPairGenerator() { }

  private static class Holder {
    private static final KeyPairGenerator INSTANCE;

    static {
      try {
        INSTANCE = KeyPairGenerator.getInstance(ALGORITHM);
        INSTANCE.initialize(ED25519_CURVE);
      } catch (NoSuchAlgorithmException ex) {
        throw new AssertionError(algorithmAssertionMsg, ex);
      } catch (InvalidAlgorithmParameterException ex) {
        throw new AssertionError(keySpecAssertionMsg, ex);
      }
    }
  }

  public static KeyPair generateKeyPair() {
    return Holder.INSTANCE.generateKeyPair();
  }


  public static KeyPairGenerator getInstance(final Provider provider, final SecureRandom random) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM, provider);
      gen.initialize(ED25519_CURVE, random);
      return gen;
    } catch (NoSuchAlgorithmException ex) {
      throw new AssertionError(algorithmAssertionMsg, ex);
    } catch (InvalidAlgorithmParameterException ex) {
      throw new AssertionError(keySpecAssertionMsg, ex);
    }
  }
}
