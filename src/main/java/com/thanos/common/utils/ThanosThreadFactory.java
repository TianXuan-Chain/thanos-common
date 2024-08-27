package com.thanos.common.utils;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ThanosThreadFactory.java description：
 *
 * @Author laiyiyu create on 2020-11-19 11:16:44
 */
public class ThanosThreadFactory implements ThreadFactory {

    private AtomicInteger threadIndex = new AtomicInteger(0);

    public final String baseName;

    public ThanosThreadFactory(String baseName) {
        this.baseName = baseName;
    }

    @Override
    public Thread newThread(Runnable r) {
        return new Thread(r, String.format("%s_thread%d", baseName, this.threadIndex.incrementAndGet()));
    }
}
