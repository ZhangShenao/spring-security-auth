package spring.boot.security.handler;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author ZhangShenao
 * @date 2022/12/31 4:35 PM
 * Description 全局异常处理器
 */
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public String onException(Exception e) {
        return "访问异常: " + e.getMessage();
    }
}
