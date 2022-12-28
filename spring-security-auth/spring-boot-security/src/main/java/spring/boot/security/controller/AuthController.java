package spring.boot.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.boot.security.dto.UserResourceDto;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author ZhangShenao
 * @date 2022/12/28 5:07 PM
 * Description 身份认证API
 */
@RestController
@RequestMapping("/auth")
public class AuthController {
    @GetMapping("/current_username_by_principal")
    public String getCurrentUsernameByPrincipal(Principal principal) {
        //基于SpringSecurity的Principal获取当前登录用户信息
        return principal.getName();
    }

    @GetMapping(value = "/current_username_by_authentication")
    public String getCurrentUsernameByAuthentication(Authentication authentication) {
        //基于SpringSecurity的Authentication获取当前登录用户信息
        return authentication.getName();
    }

    @GetMapping(value = "/current_username_by_request")
    public String currentUserNameSimple(HttpServletRequest request) {
        //基于请求获取当前登录用户信息
        Principal principal = request.getUserPrincipal();
        return principal.getName();
    }

    /**
     * 获取当前登录用户及资源信息
     */
    @GetMapping("/current_user")
    public UserResourceDto currentUser() {
        //基于SecurityContextHolder获取当前登录用户信息
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        if (user == null) {
            return null;
        }
        UserResourceDto userResourceDto = new UserResourceDto();
        userResourceDto.setUsername(user.getUsername());

        //用户授权的资源
        List<String> resources = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .orElse(Collections.emptyList())
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        userResourceDto.setResources(resources);
        return userResourceDto;
    }
}
