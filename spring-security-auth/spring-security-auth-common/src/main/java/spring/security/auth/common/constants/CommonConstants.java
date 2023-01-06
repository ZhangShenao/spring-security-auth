package spring.security.auth.common.constants;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:39 PM
 * Description 通用常量定义
 */
public interface CommonConstants {
    String USER_SESSION_KEY = "current_user";   //用户信息Session Key

    String AUTH_URL_PREFIX = "/auth";   //认证url前缀
    String MOBILE_URL_PREFIX = "/mobile";   //手机号url前缀
    String SALARY_URL_PREFIX = "/salary";   //薪酬url前缀

    String MOBILE_RESOURCE_KEY = "mobile";  //手机号资源key
    String SALARY_RESOURCE_KEY = "salary";  //薪酬资源key
}
