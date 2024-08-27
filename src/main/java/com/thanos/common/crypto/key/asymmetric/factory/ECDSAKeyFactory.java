package com.thanos.common.crypto.key.asymmetric.factory;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.ec.ECKey;

import java.security.SecureRandom;

/**
 * 类ECKeyFactory.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 19:53
 */

public class ECDSAKeyFactory extends SecureKeyFactory {
    @Override
    public SecureKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return ECKey.fromPrivate(privKeyBytes, shardingNumber);
    }

    @Override
    public SecureKey getInstance(short shardingNumber) {
        return new ECKey(shardingNumber);
    }

    @Override
    public SecureKey getInstance(SecureRandom secureRandom, short shardingNumber) {
        return new ECKey(secureRandom, shardingNumber);
    }
}
