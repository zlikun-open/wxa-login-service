package com.zlikun.open.configure;

import okhttp3.OkHttpClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/**
 * @author zlikun
 * @date 2018-09-12 10:48
 */
@Configuration
public class AppConfigure {

    @Bean
    public OkHttpClient httpClient() {
        return new OkHttpClient.Builder()
                .connectTimeout(1500, TimeUnit.MILLISECONDS)
                .build();
    }

}
