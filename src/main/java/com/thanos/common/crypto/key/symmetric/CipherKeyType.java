package com.thanos.common.crypto.key.symmetric;

/**
 * CipherKeyType.java的实现描述：密钥算法类型
 *
 * @author xuhao create on 2020/11/12 14:58
 */

public enum CipherKeyType {
    AES(11, "AES"),
    SM4(12, "SM4");

    private int code;

    private String description;


    CipherKeyType(int code, String description) {
        this.code = code;
        this.description = description;
    }

    public int getCode() {
        return code;
    }


    public String getDescription() {
        return description;
    }

    public static CipherKeyType getKeyTypeByCode(int code) {
        for (CipherKeyType item : CipherKeyType.values()) {
            if (item.getCode() == code) {
                return item;
            }
        }
        return null;
    }

    public static CipherKeyType getKeyTypeByDescription(String description) {
        for (CipherKeyType item : CipherKeyType.values()) {
            if (item.getDescription().equalsIgnoreCase(description)) {
                return item;
            }
        }
        return null;
    }
}
