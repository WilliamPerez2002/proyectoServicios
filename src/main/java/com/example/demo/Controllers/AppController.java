package com.example.demo.Controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class AppController {



    @GetMapping("/login")
    public String loginPage(@RequestParam(name = "error", required = false) String error, @RequestParam(name = "logout", required = false) String logout,  Model model) {
        if (error != null && !error.isEmpty()) {
            model.addAttribute("error", "Mensaje de error personalizado");
        }
        if (logout != null && !logout.isEmpty()) {
            model.addAttribute("logout", "Mensaje de error personalizado");
        }



        return "login.html"; // Esto corresponde al nombre de tu archivo HTML de login
    }

    @GetMapping("/users")
    public String userPage(Model model) {
        // Aquí puedes agregar lógica adicional si es necesario
        return "user.html"; // Esto corresponde al nombre de tu archivo HTML de login
    }

    @GetMapping("/")
    public String principalPage(Model model) {
        // Aquí puedes agregar lógica adicional si es necesario
        return "home.html"; // Esto corresponde al nombre de tu archivo HTML de login
    }

    @GetMapping("/error")
    public String errorPage(Model model){
        return "error.html";
    }



}
