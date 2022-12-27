package basic.auth.controller;

import basic.auth.bean.UserBean;
import basic.auth.constants.CommonConstants;
import basic.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:21 PM
 * Description 认证API
 */
@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {
    @Resource
    private AuthService authService;

    /**
     * 登录
     */
    @GetMapping("/login")
    public UserBean login(@RequestParam("user_name") String userName, @RequestParam("password") String password, HttpServletRequest request) {
        Optional<UserBean> user = authService.login(userName, password);
        if (user.isPresent()) { //登录成功,将用户信息保存至Session
            log.info("用户登录成功! userName: {}, password: {}", userName, password);
            request.getSession().setAttribute(CommonConstants.USER_SESSION_KEY, user.get());
            return user.get();
        }
        log.error("用户登录是吧! userName: {}, password: {}", userName, password);
        return null;
    }

    /**
     * 获取当前登录用户信息
     */
    @GetMapping("/current_user")
    public Object getCurrentUser(HttpServletRequest request){
        return request.getSession().getAttribute(CommonConstants.USER_SESSION_KEY);
    }

    /**
     * 登出
     */
    @GetMapping("/logout")
    public void logout(HttpServletRequest request){
        request.getSession().removeAttribute(CommonConstants.USER_SESSION_KEY);
    }
}
