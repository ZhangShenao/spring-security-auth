package distributed.resource.service.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.auth.common.constants.CommonConstants;

/**
 * @author ZhangShenao
 * @date 2023/1/6 2:28 PM
 * Description 薪水API
 */
@RestController
@RequestMapping(CommonConstants.SALARY_URL_PREFIX)
public class SalaryController {
    @PreAuthorize("hasAuthority('salary')") //通过注解进行安全认证,要求用户必须具有指定资源的权限才可以访问
    @GetMapping("/query")
    public String query() {
        return "$99999.99";
    }
}
