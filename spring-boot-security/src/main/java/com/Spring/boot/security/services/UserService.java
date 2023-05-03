package com.Spring.boot.security.services;

import com.Spring.boot.security.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    List<User> list=new ArrayList<>();

    public UserService() {
        list.add(new User("Shivam kumar","shivam123","shivamkr4192@gmail.com"));
        list.add(new User("Vivek singh","vivek123","kayal@gmail.com"));
    }
    public List<User> getAllUser(){
        return this.list;
    }

    public  User getUser(String username){
        return this.list.stream().filter((user)->user.getUsername().equals(username)).findAny().orElse(null);
    }

    public User addUser(User user){
        this.list.add(user);
        System.out.println(user);
        return user;
    }
}
