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
package com.thanos.common.crypto;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import sun.security.ec.SunEC;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

import java.security.Provider;
import java.security.Security;

public final class CastleProvider {

    private static class Holder {

        private static final Provider SPONGY_INSTANCE;

        private static final Provider BOUNCY_INSTANCE;

        private static final Provider JSSE_INSTANCE;

        static {

            SPONGY_INSTANCE = new org.spongycastle.jce.provider.BouncyCastleProvider();

            BOUNCY_INSTANCE = new org.bouncycastle.jce.provider.BouncyCastleProvider();

            JSSE_INSTANCE = new BouncyCastleJsseProvider();

            SPONGY_INSTANCE.put("MessageDigest.ETH-KECCAK-256", "com.thanos.common.crypto.cryptohash.Keccak256");

            SPONGY_INSTANCE.put("MessageDigest.ETH-KECCAK-256-LIGHT", "com.thanos.common.crypto.cryptohash.Keccak256Light");

            SPONGY_INSTANCE.put("MessageDigest.ETH-KECCAK-512", "com.thanos.common.crypto.cryptohash.Keccak512");

            //jdk1.8 此处替换是为了确保java.security中的provider列表正确（即用BC库替换SunEC）。
            // 如果不删除SunEC，只在表尾加BC库，那么SunEC顺序在BC库之前，结果是在国密tls中，优先使用SunEC识别国密曲线，导致识别失败。，
            // 如果在表头添加BC库，虽然能解决上述问题，但会导致SM4生成失败（具体原因待确认）。故只能采取替换策略。
            Security.removeProvider("SunEC");
            Security.insertProviderAt(BOUNCY_INSTANCE, 3);

//            Security.addProvider(BOUNCY_INSTANCE);
            Security.addProvider(JSSE_INSTANCE);
            Security.addProvider(SPONGY_INSTANCE);
            Security.addProvider(new SunEC());
        }
    }

    public static Provider getSpongyInstance() {
        return Holder.SPONGY_INSTANCE;
    }

    public static Provider getBouncyInstance() {
        return Holder.BOUNCY_INSTANCE;
    }

    public static Provider getJsseInstance() {
        return Holder.JSSE_INSTANCE;
    }
//
//    public static void main(String[] args) {
//        CastleProvider.getBouncyInstance();
//        Provider[] providers = Security.getProviders();
//        System.out.println(providers.length);
//        for(int i=0;i<providers.length;i++){
//            System.out.println(providers[i].getName());
//        }
//    }
}
