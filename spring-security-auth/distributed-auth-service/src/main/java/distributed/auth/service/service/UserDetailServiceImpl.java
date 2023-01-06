package distributed.auth.service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import spring.security.auth.common.constants.CommonConstants;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ZhangShenao
 * @date 2022/12/29 2:03 PM
 * Description 用户服务,提供Spring Security的主体数据管理功能
 */
@Slf4j
public class UserDetailServiceImpl implements UserDetailsService {
    @Resource
    private PasswordEncoder passwordEncoder;

    private static Map<String, UserDetails> users = new HashMap<>();

    /**
     * 初始化用户主体信息
     */
    @PostConstruct
    private void init() {
        users.put("admin", User.withUsername("admin").password(passwordEncoder.encode("admin")).authorities(CommonConstants.MOBILE_RESOURCE_KEY, CommonConstants.SALARY_RESOURCE_KEY).build());
        users.put("manager", User.withUsername("manager").password(passwordEncoder.encode("manager")).authorities(CommonConstants.SALARY_RESOURCE_KEY).build());
        users.put("worker", User.withUsername("worker").password(passwordEncoder.encode("worker")).authorities("worker")/*.disabled(true)*/.build());   //用户有4种状态,可以被禁用
        log.info("User Detail Initialized");
    }

    /**
     * 根据用户名,加载用户主体信息
     */
    @Override
    public UserDetails loadUserByUsername(String username) {
        return users.get(username);
    }
}
