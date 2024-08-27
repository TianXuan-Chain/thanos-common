package com.thanos.common.crypto.key.asymmetric.factory;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.ed.EDKey;

import java.security.SecureRandom;

/**
 * 类EDKeyFactory.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 19:53
 */

public class EDKeyFactory extends SecureKeyFactory {
    @Override
    public SecureKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return EDKey.fromPrivate(privKeyBytes, shardingNumber);
    }

    @Override
    public SecureKey getInstance(short shardingNumber) {
        return new EDKey(shardingNumber);
    }

    @Override
    public SecureKey getInstance(SecureRandom secureRandom, short shardingNumber) {
        return new EDKey(secureRandom, shardingNumber);
    }
}
