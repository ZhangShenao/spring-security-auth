package distributed.resource.service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import spring.security.auth.common.constants.CommonConstants;

/**
 * @author ZhangShenao
 * @date 2023/1/6 2:29 PM
 * Description 安全配置
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)    //开启基于注解的方法级别安全认证
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers(CommonConstants.SALARY_URL_PREFIX + "/**")
//                .hasAuthority("salary") //这里采用了注解的方法级权限配置。
                .authenticated()
                .anyRequest().permitAll();
    }
}
