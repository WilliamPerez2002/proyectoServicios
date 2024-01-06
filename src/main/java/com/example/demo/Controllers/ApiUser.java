package com.example.demo.Controllers;


import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("users")
public class ApiUser {

    @Autowired
    UserRepository userRepository;



    @PostMapping("/search")
    public User searchbyUserName(@RequestBody String username){
        return userRepository.findByUsername(username);
    }


    public User searchByemail(@RequestBody String email){return userRepository.findByEmail(email);}
}
