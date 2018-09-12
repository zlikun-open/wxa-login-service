package com.zlikun.open.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

/**
 * @author zlikun
 * @date 2018-09-12 10:59
 */
@Service
public class TokenService {

    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 创建token，并映射token与openId和sessionKey的关系
     *
     * @param openId
     * @param sessionKey
     * @return
     */
    public String createToken(String openId, String sessionKey) {
        String token = DigestUtils.md5DigestAsHex((String.format("%s:%s", openId, sessionKey)).getBytes());
        BoundHashOperations<String, String, String> bho = redisTemplate.boundHashOps(token);
        bho.put("openId", openId);
        bho.put("sessionKey", sessionKey);
        return token;
    }

    /**
     * 根据token查询openId
     *
     * @param token
     * @return
     */
    public String queryOpenId(String token) {
        return (String) redisTemplate.boundHashOps(token).get("openId");
    }

    /**
     * 根据token查询sessionKey
     *
     * @param token
     * @return
     */
    public String querySessionKey(String token) {
        return (String) redisTemplate.boundHashOps(token).get("sessionKey");
    }

}
