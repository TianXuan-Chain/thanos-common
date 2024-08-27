package com.thanos.common.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * BlockingPutHashMap.java description：
 *
 * @Author laiyiyu create on 2021-01-11 10:00:18
 */
public class BlockingPutHashMap<K, V>  {

    private static final Logger logger = LoggerFactory.getLogger("utils");

    final ReentrantLock lock;

    /** Condition for waiting puts */
    private final Condition notFull;

    final int blockSize;

    private HashMap<K, V> hashMap;

    public BlockingPutHashMap(int blockSize) {
        this.blockSize = blockSize;
        this.hashMap = new HashMap<>(blockSize);
        lock = new ReentrantLock(true);
        notFull =  lock.newCondition();
    }

    public void put(K key, V value) throws InterruptedException {
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            while (blockSize == hashMap.size()) {
                notFull.await();
//                if (logger.isDebugEnabled()) {
//                    logger.debug("BlockingPutHashMap is full, please await!");
//                }
            }


            this.hashMap.put(key, value);
        } finally {
            lock.unlock();
        }
    }

    public V remove(K key) throws InterruptedException {
        V result;
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {

            result = this.hashMap.remove(key);

            if (result == null) return null;

            notFull.signal();
            return result;
        } finally {
            lock.unlock();
        }
    }

    public V get(K key) throws InterruptedException {
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            return this.hashMap.get(key);
        } finally {
            lock.unlock();
        }
    }
}
