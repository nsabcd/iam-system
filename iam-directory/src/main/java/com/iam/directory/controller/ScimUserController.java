package com.iam.directory.controller;

import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("scim/v2")
public class ScimUserController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public ScimUserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("/Users")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody Map<String, Object> scimUser){
        String userName = (String)scimUser.get("userName");
        List<Map<String, String>> emails = (List<Map<String, String>>) scimUser.get("emails");
        String email = emails!=null && !emails.isEmpty() ? emails.get(0).get("value") : userName+"iam.com";

        if(userRepository.findByUsername(userName).isPresent()){
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("status", "409", "detail", "User already exists"));
        }

        UserEntity user = new UserEntity();
        user.setUsername(userName);
        user.setEmail(email);
        //TO DO: random password
        user.setPasswordHash(passwordEncoder.encode("DefaultPass123!"));
        user.setActive(true);

        UserEntity savedUser = userRepository.save(user);

        // Return SCIM 2.0 compliant response structure
        Map<String, Object> response = Map.of(
                "schemas",List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                "id",savedUser.getId().toString(),
                "userName",savedUser.getUsername(),
                "active", savedUser.isActive()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/Users/{id}")
    public ResponseEntity<Object> getUser(@PathVariable UUID id){
        return userRepository.findById(id)
                .<ResponseEntity<Object>>map(user -> ResponseEntity.ok(Map.of(
                            "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                            "id", user.getId().toString(),
                            "userName", user.getUsername(),
                            "active", user.isActive()
                        ))).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "404", "detail", "User not found")));
    }

    @DeleteMapping("/Users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable("id") String id) {
        // Perform user deletion logic using your directory/service layer
        userRepository.deleteById(UUID.fromString(id));

        // Return 204 No Content upon successful deletion
        return ResponseEntity.noContent().build();
    }
}
