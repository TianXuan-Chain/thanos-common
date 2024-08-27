package com.thanos.common.utils;



/**
 * 类 OperateSystemUtil.java的实现描述：
 *
 * @Author laiyiyu create on 2020-01-14 16:37:10
 */
public class OperateSystemUtil {

    public static final String OS_NAME = System.getProperty("os.name");

    private static boolean IS_LINUX_PLATFORM = false;

    static {
        if (OS_NAME != null && OS_NAME.toLowerCase().contains("linux")) {
            IS_LINUX_PLATFORM = true;
        }
    }



    public static boolean isLinuxPlatform() {
        return IS_LINUX_PLATFORM;
    }
}
