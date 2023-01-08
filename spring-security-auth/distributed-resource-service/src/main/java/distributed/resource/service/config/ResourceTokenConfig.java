package distributed.resource.service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;


import static spring.security.auth.common.constants.CommonConstants.JWT_SIGN_KEY;

/**
 * @author ZhangShenao
 * @date 2023/1/4 3:02 PM
 * Description 资源服务令牌配置
 */
@Configuration
public class ResourceTokenConfig {
    /**
     * 注入JWT Token转换器
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConvert() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(JWT_SIGN_KEY);
        return converter;
    }

    /**
     * 注入Token存储服务,这里使用JWT
     */
    @Bean
    public TokenStore tokenStore() {
        //使用默认的基于内存的方式来存储Token
//        return new InMemoryTokenStore();

        //使用JWT作为TokenStore
        return new JwtTokenStore(accessTokenConvert());
    }
}
