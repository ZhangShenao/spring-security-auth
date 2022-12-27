package basic.auth.interceptor;

import basic.auth.bean.UserBean;
import basic.auth.constants.CommonConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:45 PM
 * Description 认证拦截器
 */
@Component
@Slf4j
public class AuthInterceptor extends HandlerInterceptorAdapter {
    /**
     * 拦截请求,对当前用户进行权限认证
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String uri = request.getRequestURI();

        //跳过认证接口
        if (uri.equals("/") || uri.contains(".") || uri.startsWith(CommonConstants.AUTH_URL_PREFIX)) {
            return true;
        }

        //未登录用户,直接拒绝访问
        Object currentUser = request.getSession().getAttribute(CommonConstants.USER_SESSION_KEY);
        if (!(currentUser instanceof UserBean)) {
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("Please Login First");
            return false;
        }

        //已登录用户,判断是否有资源访问权限
        UserBean user = (UserBean) currentUser;
        if (uri.startsWith(CommonConstants.MOBILE_URL_PREFIX)) {
            boolean hasAuth = user.hasPermission(CommonConstants.MOBILE_RESOURCE_KEY);
            if (!hasAuth) {
                log.error("User Has No Auth");
            }
            return hasAuth;
        }
        if (uri.startsWith(CommonConstants.SALARY_URL_PREFIX)) {
            boolean hasAuth = user.hasPermission(CommonConstants.SALARY_RESOURCE_KEY);
            if (!hasAuth) {
                log.error("User Has No Auth");
            }
            return hasAuth;
        }

        //无资源访问权限
        return false;
    }
}
