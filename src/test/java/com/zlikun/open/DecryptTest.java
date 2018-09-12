package com.zlikun.open;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

/**
 * 测试微信小程序获取用户数据解密操作
 *
 * @author zlikun
 * @date 2018-09-12 16:18
 */
public class DecryptTest {

    final String algorithm = "AES/CBC/PKCS7Padding";

    String sessionKey = "TX3ngXDJDNzZrxH/DuHZRg==";
    String encryptedData = "uh05BpG+KEoCQ2GybYdRq5RCwyUXERAH8vxssOUUzu9XyE5x9QnA8fUTiyPAuG3EfLhlg1ybUSxh4P0zrKEa66PrHtEXH5zQVjP/cCYEUu5JH/p4RsPVhNMm1kb7ardtAzraFNlUed0XIPzQsHgz+cpCB4GsNS4L8Xye5RJvKucrNKaOFtmgvTrsQyyLHuO5rwJqoK0XDwEhErZHy0w8HZutvsm1eEwlhmG9scykBPvxYC4eqoUcXri2B6C55qZa1WkIzy9M9O1ZpP8dcQKnTUBsRRICGKPMBsmGJmoUOQJO2c57e+azTJDG0Sc8oFC9x+aGUgKifawz5lA+KtnktUKt+TXkigHrFDAFnDS0CmxOltGXm8CMKHy7lemDvDRXyBYUAa1s4Uw84cFXvdPMOe/n2hp0AG4PuHPw3wL19WHMydUYRX7t+LFPrXmiSAw5kehcAHvSzVjdVgsy5u6POA==";
    String iv = "WJBlOP4crWRwDtrfr+wEfA==";

    @BeforeClass
    public static void init() {
        // 提供加密算法提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * https://developers.weixin.qq.com/miniprogram/dev/api/signature.html#加密数据解密算法
     * 1. 需要添加JCE限制文件
     * 2. 需要添加 bcprov-jdk15on 依赖，否则没有 AES/CBC/PKCS7Padding 加密算法提供者
     */
    @Test
    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException {

        // 1. 对称解密使用的算法为 AES-128-CBC，数据采用PKCS#7填充
        Cipher cipher = Cipher.getInstance(algorithm);

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
        byte[] original = cipher.doFinal(encrypted);

        // 打印原文，格式化JSON见底部
        // 实际重要的信息就一个 openId ，前面已经得到了，说好的unionId呢？！
        // {"openId":"oNQ6p5a1D9ACmIGHXD82CoLydM8Q","nickName":"张立坤","gender":1,"language":"zh_CN","city":"","province":"","country":"中国","avatarUrl":"https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIbokXDSvh8RNZTVYIFPu3RFw1UAfV7ZZ8Rh2RUTWzcwSvM7h8CxYAxjQRcYOk2nvWGicqIqTriaj8A/132","watermark":{"timestamp":1536742178,"appid":"wx495c4fd39759eb87"}}
        System.out.println(new String(original));

    }

}
/* ------------------------------------------------------------------------------------------------------------------------------------
 {
     "openId": "oNQ6p5a1D9ACmIGHXD82CoLydM8Q",
     "nickName": "张立坤",
     "gender": 1,
     "language": "zh_CN",
     "city": "",
     "province": "",
     "country": "中国",
     "avatarUrl": "https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIbokXDSvh8RNZTVYIFPu3RFw1UAfV7ZZ8Rh2RUTWzcwSvM7h8CxYAxjQRcYOk2nvWGicqIqTriaj8A/132",
     "watermark": {
         "timestamp": 1536742178,
         "appid": "wx495c4fd39759eb87"
     }
 }
------------------------------------------------------------------------------------------------------------------------------------ */
