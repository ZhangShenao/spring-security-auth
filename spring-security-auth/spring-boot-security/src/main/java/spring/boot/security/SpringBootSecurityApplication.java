package spring.boot.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author ZhangShenao
 * @date 2022/12/28 4:38 PM
 * Description 启动类
 */
@SpringBootApplication
@EnableWebSecurity  //注解开启SpringBoot Security
public class SpringBootSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityApplication.class, args);
    }
}
