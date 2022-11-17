package com.oracle.choongangGroup.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class testController {
	
	@RequestMapping(value = "/")
    ModelAndView root() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject("test", "테스트 내용입니다.");
        modelAndView.setViewName("index");
        return modelAndView;
    }

    @RequestMapping(value = "/content")
    public String test() {
        return "views/content";
    }
}
