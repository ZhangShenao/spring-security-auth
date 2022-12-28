package spring.boot.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ZhangShenao
 * @date 2022/12/27 3:20 PM
 * Description 薪水API,是需要纳入权限控制的访问资源
 */
@RestController
@RequestMapping("/salary")
public class SalaryController {
    /**
     * 查询薪资
     */
    @GetMapping("/query")
    public String query() {
        return "￥999999";
    }
}
