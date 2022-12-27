package basic.auth.bean;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:12 PM
 * Description RBAC模型——Role对象
 */
@Data
@AllArgsConstructor
public class RoleBean {
    private long id;    //角色ID
    private String name;    //角色名

    private List<ResourceBean> resources;   //角色所拥有的资源列表
}
