package com.bezkoder.springjwt.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/oauth2")
public class GoogleController {
    @GetMapping("/google")
    public ModelAndView google() {
        ModelAndView modelAndView = new ModelAndView("googleAuth");	
        return modelAndView;
    }
    
    @GetMapping("/home")
    public String googleHome() {
    	return "Success................";
    }
}

 	