package com.zlikun.open.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

/**
 * 加解密工具类
 *
 * @author zlikun
 * @date 2018-09-12 16:57
 */
public class EncryptUtils {

    private static final String algorithm = "AES/CBC/PKCS7Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 小程序AES解密
     * @param sessionKey
     * @param iv
     * @param encryptedData
     * @return
     */
    public static final byte[] wxaAesDecrypt(String sessionKey, String iv, String encryptedData) {

        Cipher cipher = null;
        try {
            // 1. 对称解密使用的算法为 AES-128-CBC，数据采用PKCS#7填充
            cipher = Cipher.getInstance(algorithm);

            // 2. 对称解密的目标密文为 Base64_Decode(encryptedData)
            byte[] encrypted = Base64.decodeBase64(encryptedData);

            // 3. 对称解密秘钥 aeskey = Base64_Decode(session_key), aeskey 是16字节
            byte[] aesKey = Base64.decodeBase64(sessionKey);

            // 4. 对称解密算法初始向量 为Base64_Decode(iv)，其中iv由数据接口返回。
            AlgorithmParameters ivParam = AlgorithmParameters.getInstance("AES");
            ivParam.init(new IvParameterSpec(Base64.decodeBase64(iv)));

            // 执行解密操作
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParam);
            return cipher.doFinal(encrypted);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }

        return null;
    }

}
