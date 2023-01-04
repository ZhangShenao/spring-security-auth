package distributed.auth.service.config;

import distributed.auth.service.service.UserDetailServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author ZhangShenao
 * @date 2022/12/28 4:50 PM
 * Description SpringBoot Security 配置
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 注入Password Encoder，用于对用户密码进行加密
     * 最常用的为BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    /**
     * 注入UserDetailsService，用于提供合法的用户认证信息
     */
    @Bean
    public UserDetailsService userDetailsService() {
        //使用自定义的用户服务
        return new UserDetailServiceImpl();
    }

    /**
     * 从父类加载认证管理器
     */
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 配置安全认证策略
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //链式配置拦截策略
        http.csrf().disable()//关闭csrf跨域检查
                .authorizeRequests()
                .anyRequest().authenticated() //其他请求需要登录
                .and() //并行条件
                .formLogin(); //可从默认的login页面登录，并且登录后跳转到main.htmlemember_me");   //rememberMe记住我功能,会将当前登录用户的token保存到Cookie中

    }
}
