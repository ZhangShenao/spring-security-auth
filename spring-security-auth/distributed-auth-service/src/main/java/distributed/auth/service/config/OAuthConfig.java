package distributed.auth.service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import javax.annotation.Resource;

/**
 * @author ZhangShenao
 * @date 2023/1/4 2:42 PM
 * Description SpringBoot Security OAuth2配置
 */
@Configuration
@EnableAuthorizationServer  //开启OAuth认证服务
public class OAuthConfig extends AuthorizationServerConfigurerAdapter {
    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Resource
    private UserDetailsService userDetailsService;

    @Resource
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Resource
    private AuthorizationCodeServices authorizationCodeServices;


    /**
     * 1. 配置客户端详情服务
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //使用内存配置的方式维护客户端信息
        clients.inMemory()//内存方式
                .withClient("client-1") //client_id
                .secret(passwordEncoder.encode("secret-1"))//客户端秘钥
                .resourceIds("salary")//客户端拥有的资源列表
                .authorizedGrantTypes("authorization_code",
                        "password", "client_credentials", "implicit", "refresh_token")//该client允许的授权类型,这里允许了全部授权类型
                .scopes("all")//允许的授权范围
                .autoApprove(false)//跳转到授权页面
                .redirectUris("https://www.baidu.com");//回调地址
//                .and() //继续注册其他客户端
//                .withClient() //使用自定义的ClientDetailServices
    }

    /**
     * 2. 配置令牌的访问端点和令牌服务TokenService
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
//                .pathMapping("/oauth/confirm_access","/customer/confirm_access")//定制授权同意页面
                .authenticationManager(authenticationManager)//认证管理器
                .userDetailsService(userDetailsService)//密码模式的用户信息管理
                .authorizationCodeServices(authorizationCodeServices)//授权码服务
                .tokenServices(authorizationServerTokenServices)//令牌管理服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    /**
     * 3. 配置令牌端点的安全约束
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()") //开放oauth/token_key接口
                .checkTokenAccess("permitAll()") //开发oauth/check_token接口,便于资源服务器进行Token校验
                .allowFormAuthenticationForClients(); // 表单认证，申请令牌
    }


}
