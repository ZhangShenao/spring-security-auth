package basic.auth.service;

import basic.auth.bean.UserBean;
import basic.auth.dao.UserDao;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Optional;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:25 PM
 * Description 认证服务
 */
@Service
public class AuthService {
    @Resource
    private UserDao userDao;

    /**
     * 根据用户名和密码登录
     *
     * @param userName 用户名
     * @param password 密码
     * @return 登录后的用户
     */
    public Optional<UserBean> login(String userName, String password) {
        return userDao.queryByUserNameAndPassword(userName, password);
    }
}
