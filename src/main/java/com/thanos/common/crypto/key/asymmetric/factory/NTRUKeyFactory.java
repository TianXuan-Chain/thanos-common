package com.thanos.common.crypto.key.asymmetric.factory;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.ntru.NTRUKey;

import java.security.SecureRandom;

/**
 * NTRUFactory.java description：
 *
 * @Author lemon819 create on 2020-11-20 10:31:13
 */
public class NTRUKeyFactory extends SecureKeyFactory{

    @Override
    public SecureKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return NTRUKey.fromPrivate(privKeyBytes, shardingNumber);
    }

    @Override
    public SecureKey getInstance(short shardingNumber) {
        return new NTRUKey(shardingNumber);
    }

    @Override
    public SecureKey getInstance(SecureRandom secureRandom, short shardingNumber){
        return null;
    }
}

