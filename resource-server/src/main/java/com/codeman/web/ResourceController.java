package com.codeman.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author hdgaadd
 * Created on 2022/01/11
 */
@RestController
public class ResourceController {
    @RequestMapping("/user") // 必须是RequestMapping
    public String getUser() {
        return "user";
    }

    @RequestMapping("/admin")
    @PreAuthorize("hasAnyAuthority('admin')")
    public String getAdmin() {
        return "获取资源服务器数据成功";
    }
}
