package distributed.auth.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author ZhangShenao
 * @date 2023/1/4 10:20 AM
 * Description 分布式授权服务启动类
 */
@SpringBootApplication
public class DistributedAuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(DistributedAuthServiceApplication.class, args);
    }
}
