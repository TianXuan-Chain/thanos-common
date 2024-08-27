package com.thanos.common.crypto.key.asymmetric;

/**
 * CipherKeyType.java的实现描述：密钥算法类型
 *
 * @author xuhao create on 2020/11/12 14:58
 */

public enum SecureKeyType {
    ECDSA(1, "ECDSA"),
    ED25519(2, "ED25519"),
    SM(8, "SM"),
    PQC(9, "PQC");

    private int code;

    private String description;


    SecureKeyType(int code, String description) {
        this.code = code;
        this.description = description;
    }

    public int getCode() {
        return code;
    }


    public String getDescription() {
        return description;
    }

    public static SecureKeyType getKeyTypeByCode(int code) {
        for (SecureKeyType item : SecureKeyType.values()) {
            if (item.getCode() == code) {
                return item;
            }
        }
        return null;
    }

    public static SecureKeyType getKeyTypeByDescription(String description) {
        for (SecureKeyType item : SecureKeyType.values()) {
            if (item.getDescription().equalsIgnoreCase(description)) {
                return item;
            }
        }
        return null;
    }
}
