package spring.boot.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static spring.boot.security.constants.CommonConstants.*;

/**
 * @author ZhangShenao
 * @date 2022/12/28 4:50 PM
 * Description SpringBoot Security 配置
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 注入Password Encoder，用于对用户密码进行加密
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    /**
     * 注入UserDetailsService，用于提供合法的用户认证信息
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        //将用户认证信息维护在内存中,并进行指定资源的授权
        return new InMemoryUserDetailsManager(User.withUsername("admin").password(passwordEncoder().encode("admin")).authorities(MOBILE_RESOURCE_KEY, SALARY_RESOURCE_KEY).build(),
                User.withUsername("manager").password(passwordEncoder().encode("manager")).authorities(SALARY_RESOURCE_KEY).build(),
                User.withUsername("worker").password(passwordEncoder().encode("worker")).authorities("worker").build());
    }

    /**
     * 配置安全认证策略
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //链式配置拦截策略
        http.csrf().disable()//关闭csrf跨域检查
                .authorizeRequests()
                .antMatchers("/mobile/**").hasAuthority(MOBILE_RESOURCE_KEY) //配置资源权限
                .antMatchers("/salary/**").hasAuthority(SALARY_RESOURCE_KEY)
                .antMatchers("/auth/**").permitAll() //auth下的请求直接通过
                .antMatchers("/css/**").permitAll() //静态资源全部放行
                .antMatchers("/img/**").permitAll() //静态资源全部放行
                .antMatchers("/js/**").permitAll() //静态资源全部放行
                .antMatchers("/index.html").permitAll() //对首页放行
                .anyRequest().authenticated() //其他请求需要登录
                .and() //并行条件
                .formLogin().defaultSuccessUrl("/main.html")
                .failureUrl("/common/loginFailed"); //可从默认的login页面登录，并且登录后跳转到main.html
    }
}
