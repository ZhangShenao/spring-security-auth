package basic.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:18 PM
 * Description 手机号API,是需要纳入权限控制的访问资源
 */
@RestController
@RequestMapping("/mobile")
public class MobileController {
    /**
     * 查询手机号
     */
    @GetMapping("/query")
    public String query() {
        return "13812345678";
    }
}
