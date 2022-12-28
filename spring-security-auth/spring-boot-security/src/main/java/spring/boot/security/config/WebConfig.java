package spring.boot.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author ZhangShenao
 * @date 2022/12/28 4:48 PM
 * Description Web服务配置
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    /**
     * 配置启动页面
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/index.html");
    }
}
