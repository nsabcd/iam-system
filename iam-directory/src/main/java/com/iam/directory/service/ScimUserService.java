package com.iam.directory.service;

import com.iam.directory.model.UserEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ScimUserService {

    private final UserService userService;

    public ScimUserService(UserService userService) {
        this.userService = userService;
    }

    @Transactional
    public UserEntity createScimUser(Map<String, Object> scimUser) {
        String userName = (String) scimUser.get("userName");
        List<Map<String, String>> emails = (List<Map<String, String>>) scimUser.get("emails");
        String email = (emails != null && !emails.isEmpty())
                ? emails.get(0).get("value")
                : userName + "@iam.com";

        return userService.createUser(userName, email, "DefaultPass123!");
    }

    @Transactional(readOnly = true)
    public UserEntity getUserById(UUID id) {
        return userService.getById(id);
    }

    @Transactional
    public void deleteUserById(UUID id) {
        userService.deleteById(id);
    }
}