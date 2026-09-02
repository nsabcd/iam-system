package com.iam.directory.controller;

import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.UserRepository;
import com.iam.directory.service.ScimUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("scim/v2")
public class ScimUserController {
    private final ScimUserService scimUserService;

    public ScimUserController(ScimUserService scimUserService) {
        this.scimUserService = scimUserService;
    }

    @PostMapping("/Users")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody Map<String, Object> scimUser){
        UserEntity savedUser = scimUserService.createScimUser(scimUser);

        Map<String, Object> response = Map.of(
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                "id", savedUser.getId().toString(),
                "userName", savedUser.getUsername(),
                "active", savedUser.isActive()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/Users/{id}")
    public ResponseEntity<Object> getUser(@PathVariable UUID id){
        UserEntity user = scimUserService.getUserById(id);
        return ResponseEntity.ok(Map.of(
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                "id", user.getId().toString(),
                "userName", user.getUsername(),
                "active", user.isActive()
        ));
    }

    @DeleteMapping("/Users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable("id") String id) {
        scimUserService.deleteUserById(UUID.fromString(id));
        return ResponseEntity.noContent().build();
    }
}
