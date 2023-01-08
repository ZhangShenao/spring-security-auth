package distributed.auth.service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import javax.annotation.Resource;

import static spring.security.auth.common.constants.CommonConstants.JWT_SIGN_KEY;

/**
 * @author ZhangShenao
 * @date 2023/1/4 3:02 PM
 * Description OAuth令牌配置
 */
@Configuration
public class OAuthTokenConfig {
    @Resource
    private ClientDetailsService clientDetailsService;

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

    /**
     * 注入AuthorizationServerTokenServices,用于对令牌进行管理
     */
    @Bean
    @Primary
    public AuthorizationServerTokenServices tokenService() {
        DefaultTokenServices service = new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService); //客户端详情服务
        service.setSupportRefreshToken(true); //允许令牌自动刷新
        service.setTokenStore(tokenStore()); //令牌存储策略,默认内存
        service.setTokenEnhancer(accessTokenConvert()); //设置JWT令牌增强
        service.setAccessTokenValiditySeconds(7200); // 令牌默认有效期2小时
        service.setRefreshTokenValiditySeconds(259200); // 刷新令牌默认有效期3天
        return service;
    }

    /**
     * 注入AuthorizationCodeServices,设置授权码的存储和获取方式
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
}
