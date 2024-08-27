package com.thanos.common.crypto.key.asymmetric.factory;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.sm.SMKey;

import java.security.SecureRandom;

/**
 * 类SMKeyFactory.java的实现描述：
 *
 * @author xuhao create on 2020/11/19 9:33
 */

public class SMKeyFactory extends SecureKeyFactory {
    @Override
    public SecureKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return SMKey.fromPrivate(privKeyBytes, shardingNumber);
    }

    @Override
    public SecureKey getInstance(short shardingNumber) {
        return new SMKey(shardingNumber);
    }

    @Override
    public SecureKey getInstance(SecureRandom secureRandom, short shardingNumber) {
        return new SMKey(secureRandom, shardingNumber);
    }
}
