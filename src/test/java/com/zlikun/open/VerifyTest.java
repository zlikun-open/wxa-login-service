package com.zlikun.open;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author zlikun
 * @date 2018-09-12 16:03
 */
public class VerifyTest {

    String sessionKey = "QjL5QJc3bc/chtATQ7KbbA==";

    String rawData = "{\"nickName\":\"张立坤\",\"gender\":1,\"language\":\"zh_CN\",\"city\":\"\",\"province\":\"\",\"country\":\"中国\",\"avatarUrl\":\"https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIbokXDSvh8RNZTVYIFPu3RFw1UAfV7ZZ8Rh2RUTWzcwSvM7h8CxYAxjQRcYOk2nvWGicqIqTriaj8A/132\"}";
    String signature = "1b7f3f0cd9c93cb347c7c888e96276b42ad4ce2d";

    /**
     * 微信小程序获取用户信息API，返回数据签名验签测试
     * https://developers.weixin.qq.com/miniprogram/dev/api/open.html
     */
    @Test
    public void verify() {

        String signature2 = DigestUtils.sha1Hex(rawData + sessionKey);
        assertEquals(signature, signature2);

    }

}
