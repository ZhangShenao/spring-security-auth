package basic.auth.bean;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:12 PM
 * Description RBAC模型——Resource对象
 */
@Data
@AllArgsConstructor
public class ResourceBean {
    private long id;    //资源ID
    private String name;    //资源名
    private String key; //资源唯一key
    private int type;   //资源类型 1=页面元素 2=组件 3=接口
}
