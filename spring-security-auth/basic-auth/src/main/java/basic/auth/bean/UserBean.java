package basic.auth.bean;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:11 PM
 * Description RBAC模型——User对象
 */
@Data
@AllArgsConstructor
public class UserBean {
    private long id;    //用户ID
    private String name;    //用户名
    private String password;    //用户密码

    private List<RoleBean> roles;   //用户所拥有的角色列表

    private List<ResourceBean> resources;   //用户所拥有的资源列表

    /**
     * 判断用户对一个资源是否有权限
     *
     * @param resourceKey 资源key
     * @return 是否有权限
     */
    public boolean hasPermission(String resourceKey) {
        return Optional.ofNullable(resources)
                .orElse(Collections.emptyList())
                .stream()
                .anyMatch(x -> x.getKey().equalsIgnoreCase(resourceKey));
    }
}
