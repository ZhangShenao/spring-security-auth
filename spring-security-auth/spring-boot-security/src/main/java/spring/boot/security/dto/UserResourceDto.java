package spring.boot.security.dto;

import lombok.Data;

import java.util.List;

/**
 * @author ZhangShenao
 * @date 2022/12/28 5:25 PM
 * Description 用户及资源信息
 */
@Data
public class UserResourceDto {
    private String username;    //用户名
    private List<String> resources; //用户授权的资源
}
