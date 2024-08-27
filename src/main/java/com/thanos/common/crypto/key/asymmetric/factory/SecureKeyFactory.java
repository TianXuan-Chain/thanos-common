package com.thanos.common.crypto.key.asymmetric.factory;

import com.thanos.common.crypto.key.asymmetric.SecureKey;

import java.security.SecureRandom;

/**
 * 类SecureKeyFactory.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 19:51
 */


public abstract class SecureKeyFactory {

    public abstract SecureKey fromPrivate(byte[] privKeyBytes, short shardingNumber);

    public abstract SecureKey getInstance(short shardingNumber);

    public abstract SecureKey getInstance(SecureRandom secureRandom, short shardingNumber);
}
