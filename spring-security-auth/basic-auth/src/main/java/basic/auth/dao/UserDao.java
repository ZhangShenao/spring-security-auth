package basic.auth.dao;

import basic.auth.bean.ResourceBean;
import basic.auth.bean.RoleBean;
import basic.auth.bean.UserBean;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import spring.security.auth.common.constants.CommonConstants;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:26 PM
 * Description 用户Dao
 */
@Repository
@Slf4j
public class UserDao {
    private List<UserBean> allUsers;

    /**
     * 模拟从数据库中加载用户信息
     */
    @PostConstruct
    private void init() {
        allUsers = new ArrayList<>();

        //初始化资源
        ResourceBean mobileResource = new ResourceBean(1L, "手机号资源", CommonConstants.MOBILE_RESOURCE_KEY, 1);
        ResourceBean salaryResource = new ResourceBean(2L, "薪酬资源", CommonConstants.SALARY_RESOURCE_KEY, 1);
        List<ResourceBean> adminResources = new ArrayList<>();
        adminResources.add(mobileResource);
        adminResources.add(salaryResource);

        List<ResourceBean> managerResources = new ArrayList<>();
        managerResources.add(salaryResource);

        //初始化角色
        RoleBean adminRole = new RoleBean(1L, "admin", adminResources);
        RoleBean managerRole = new RoleBean(2L, "manager", managerResources);
        List<RoleBean> adminRoles = new ArrayList<>();
        adminRoles.add(adminRole);
        List<RoleBean> managerRoles = new ArrayList<>();
        managerRoles.add(managerRole);

        //初始化用户
        UserBean adminUser = new UserBean(1L, "admin", "admin", adminRoles, adminResources);
        UserBean managerUser = new UserBean(2L, "manager", "manager", managerRoles, managerResources);
        UserBean workerUser = new UserBean(3L, "worker", "worker", Collections.emptyList(), Collections.emptyList());
        allUsers.add(adminUser);
        allUsers.add(managerUser);
        allUsers.add(workerUser);

        log.info("User Data Init Success");
    }

    /**
     * 根据用户名和密码查询用户
     *
     * @param userName 用户名
     * @param password 密码
     * @return 用户信息
     */
    public Optional<UserBean> queryByUserNameAndPassword(String userName, String password) {
        return Optional.ofNullable(allUsers)
                .orElse(Collections.emptyList())
                .stream()
                .filter(x -> x.getName().equalsIgnoreCase(userName) && x.getPassword().equalsIgnoreCase(password))
                .findFirst();
    }
}
