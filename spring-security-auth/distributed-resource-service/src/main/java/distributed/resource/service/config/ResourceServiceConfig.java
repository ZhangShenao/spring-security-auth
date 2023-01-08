package distributed.resource.service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import spring.security.auth.common.constants.CommonConstants;

import javax.annotation.Resource;

/**
 * @author ZhangShenao
 * @date 2023/1/6 2:14 PM
 * Description 资源服务配置
 */
@EnableResourceServer   //开启资源服务
@Configuration
public class ResourceServiceConfig extends ResourceServerConfigurerAdapter {
    @Resource
    private TokenStore tokenStore;

    /**
     * 1. 资源服务配置
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(CommonConstants.SALARY_RESOURCE_KEY)   //制定资源ID
//                .tokenServices(tokenServices()) //设置TokenService,即如何验证Token的有效性
                .tokenStore(tokenStore) //设置JWT TokenStore,就不需要再去远程认证服务器验证Token了,直接本地解码验证即可
                .stateless(true);   //无状态模式
    }

    /**
     * 2. Http安全策略配置
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests() //校验请求
                .antMatchers(CommonConstants.SALARY_URL_PREFIX + "/**") // 路径匹配规则
                .access("#oauth2.hasScope('all')") // 需要匹配scope,这里为all
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    /**
     * 注入TokenService,用于管理Token、验证Token有效性等
     */
//    public ResourceServerTokenServices tokenServices() {
//        //如果资源服务和授权服务是在同一个应用程序上,那可以使用DefaultTokenServices
//
//        //使用RemoteTokenServices,通过远程的授权服务验证Token的合法性
//        RemoteTokenServices services = new RemoteTokenServices();
//        services.setCheckTokenEndpointUrl("http://localhost:8080/distributed/auth/service/oauth/check_token");  //指定Token验证url
//        services.setClientId("client-1");   //client_id
//        services.setClientSecret("secret-1"); //客户端秘钥
//        return services;
//    }
}
