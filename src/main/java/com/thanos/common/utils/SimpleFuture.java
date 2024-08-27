package com.thanos.common.utils;

import java.util.concurrent.CountDownLatch;

/**
 * SimpleFuture.java description：
 *
 * @Author laiyiyu create on 2021-01-07 15:40:33
 */
public class SimpleFuture<T> {

    private CountDownLatch await = new CountDownLatch(1);

    private volatile T result;

    public T get() {
        try {
            await.await();
        } catch (InterruptedException e) {
        }
        return result;
    }

    public void set(T result) {
        this.result = result;
        await.countDown();
    }

    public void clear() {
        result = null;
    }
}
