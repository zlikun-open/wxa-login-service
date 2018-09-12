package com.zlikun.open.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zlikun.open.service.TokenService;
import com.zlikun.open.util.EncryptUtils;
import lombok.extern.slf4j.Slf4j;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

/**
 * @author zlikun
 * @date 2018-09-12 10:48
 */
@Slf4j
@RestController
@RequestMapping("/wxa")
public class WxaLoginController {

    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private OkHttpClient client;
    @Autowired
    private TokenService tokenService;

    @Value("${wxa.appid}")
    private String appId;
    @Value("${wxa.app_secret}")
    private String appSecret;
    private String wxUrl = "https://api.weixin.qq.com/sns/jscode2session";
    private String grantType = "authorization_code";

    private String KEY_OPEN_ID = "openid";
    private String KEY_SESSION_KEY = "session_key";

    /**
     * 通过微信API获取openid和session_key信息，但通常不能获取到unionId信息<br>
     * https://developers.weixin.qq.com/miniprogram/dev/api/api-login.html<br>
     * https://developers.weixin.qq.com/miniprogram/dev/api/unionID.html<br>
     *
     * @param code
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<?> doLogin(String code) throws IOException {

        // 根据code获取session_key等信息
        // code = 011h7xRW0NVXqU1NBlTW0TVlRW0h7xRW
        log.info("code = {}", code);

        Request request = new Request.Builder()
                .url(wxUrl)
                .post(new FormBody.Builder()
                        .add("appid", appId)
                        .add("secret", appSecret)
                        .add("js_code", code)
                        .add("grant_type", grantType)
                        .build())
                .build();

        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {

            String content = response.body().string();

            // content = {"session_key":"j5aJUzWfP4yt5IHKa0MLng==","openid":"oNQ6p5a1D9ACmIGHXD82CoLydM8Q"}
            log.info("content = {}", content);

            // 提取session_key和openid字段
            Map<String, String> data = mapper.readValue(content, Map.class);

            // data = {session_key=j5aJUzWfP4yt5IHKa0MLng==, openid=oNQ6p5a1D9ACmIGHXD82CoLydM8Q}
            log.info("data = {}", data);

            // 判断data容器中的字段
            // openid, session_key[, unionid]
            // errcode, errmsg
            if (data.get(KEY_OPEN_ID) != null) {
                // 获取openid和session_key信息
                String openId = data.get(KEY_OPEN_ID);
                String sessionKey = data.get(KEY_SESSION_KEY);
                // 加密生成token返回客户端，服务端映射token与openid和session_key关系
                String token = tokenService.createToken(openId, sessionKey);
                log.info("token = {}", token);
                return ResponseEntity.ok(token);
            } else {

            }

        }

        // 返回500状态码
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    /**
     * 对用户数据进行验签
     *
     * @return
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifySignature(String token, String rawData, String signature) {
        // token = b3b8ccfe2ab48783a0c671eaf384dae6
        log.info("token = {}", token);
        // rawData = {"nickName":"张立坤","gender":1,"language":"zh_CN","city":"","province":"","country":"中国","avatarUrl":"https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIbokXDSvh8RNZTVYIFPu3RFw1UAfV7ZZ8Rh2RUTWzcwSvM7h8CxYAxjQRcYOk2nvWGicqIqTriaj8A/132"}
        log.info("rawData = {}", rawData);
        // signature = 1b7f3f0cd9c93cb347c7c888e96276b42ad4ce2d
        log.info("signature = {}", signature);

        // 对rawData和sessionKey拼接字符串进行SHA-1签名
        String signature2 = DigestUtils.sha1Hex(rawData + tokenService.querySessionKey(token));
        log.info("signature2 = {}", signature2);

        // 比较API返回签名与重新计算签名是否一致
        return ResponseEntity.ok(signature.equals(signature2));
    }

    /**
     * 解密查询用户API返回数据中的密文，提供敏感信息
     * https://developers.weixin.qq.com/miniprogram/dev/api/signature.html#加密数据解密算法
     *
     * @return
     */
    @PostMapping("/decrypt")
    public ResponseEntity<?> decrypt(String token, String encryptedData, String iv) {

        // token = 28675f0e67794b08dc32a89df700e4de
        // sessionKey = TX3ngXDJDNzZrxH/DuHZRg==
        log.info("token = {}", token);
        // encryptedData = uh05BpG+KEoCQ2GybYdRq5RCwyUXERAH8vxssOUUzu9XyE5x9QnA8fUTiyPAuG3EfLhlg1ybUSxh4P0zrKEa66PrHtEXH5zQVjP/cCYEUu5JH/p4RsPVhNMm1kb7ardtAzraFNlUed0XIPzQsHgz+cpCB4GsNS4L8Xye5RJvKucrNKaOFtmgvTrsQyyLHuO5rwJqoK0XDwEhErZHy0w8HZutvsm1eEwlhmG9scykBPvxYC4eqoUcXri2B6C55qZa1WkIzy9M9O1ZpP8dcQKnTUBsRRICGKPMBsmGJmoUOQJO2c57e+azTJDG0Sc8oFC9x+aGUgKifawz5lA+KtnktUKt+TXkigHrFDAFnDS0CmxOltGXm8CMKHy7lemDvDRXyBYUAa1s4Uw84cFXvdPMOe/n2hp0AG4PuHPw3wL19WHMydUYRX7t+LFPrXmiSAw5kehcAHvSzVjdVgsy5u6POA==
        log.info("encryptedData = {}", encryptedData);
        // iv = WJBlOP4crWRwDtrfr+wEfA==
        log.info("iv = {}", iv);

        byte[] original = EncryptUtils.wxaAesDecrypt(tokenService.querySessionKey(token), iv, encryptedData);
        // original => {"openId":"oNQ6p5a1D9ACmIGHXD82CoLydM8Q","nickName":"张立坤","gender":1,"language":"zh_CN","city":"","province":"","country":"中国","avatarUrl":"https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTIbokXDSvh8RNZTVYIFPu3RFw1UAfV7ZZ8Rh2RUTWzcwSvM7h8CxYAxjQRcYOk2nvWGicqIqTriaj8A/132","watermark":{"timestamp":1536743020,"appid":"wx495c4fd39759eb87"}}
        log.info("original => {}", new String(original));

        return ResponseEntity.ok("OK");
    }

}
