package spring.boot.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import spring.boot.security.service.UserDetailServiceImpl;

import static spring.security.auth.common.constants.CommonConstants.MOBILE_RESOURCE_KEY;
import static spring.security.auth.common.constants.CommonConstants.SALARY_RESOURCE_KEY;

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
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        //使用自定义的用户服务
        return new UserDetailServiceImpl();
    }

    /**
     * 配置安全认证策略
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //链式配置拦截策略
//        http.csrf().disable()   //默认开启CSRF校验,前端通过一个hidden的表单字段,将csrf_token传到后端,后端通过CsrfFilter拦截器获取csrf_token后,保存到Session中
        http.authorizeRequests()     //设置访问控制
                .antMatchers("/mobile/**").hasAuthority(MOBILE_RESOURCE_KEY) //配置资源权限
                .antMatchers("/salary/**").hasAuthority(SALARY_RESOURCE_KEY)
                .antMatchers("/auth/**").permitAll() //auth下的请求直接通过
                .antMatchers("/css/**", "/img/**", "/js/**", "/index.html").permitAll() //静态资源全部放行
                .anyRequest().authenticated() //其他请求需要登录
                .and() //并行条件
//                .formLogin().loginPage("/index.html").loginProcessingUrl("/login").defaultSuccessUrl("/main.html") //自定义登录页面
                .formLogin().defaultSuccessUrl("/main.html").failureUrl("/common/loginFailed") //可从默认的login页面登录，并且登录后跳转到main.html
                .and()
                .rememberMe().rememberMeParameter("remember_me");   //rememberMe记住我功能,会将当前登录用户的token保存到Cookie中

    }
}
