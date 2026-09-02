package com.iam.directory.service;

import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ScimUserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder ;

    public ScimUserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder=passwordEncoder;
    }

    @Transactional
    public UserEntity createScimUser(Map<String, Object> scimUser) {
        String userName = (String) scimUser.get("userName");
        List<Map<String, String>> emails = (List<Map<String, String>>) scimUser.get("emails");
        String email = (emails != null && !emails.isEmpty())
                ? emails.get(0).get("value")
                : userName + "@iam.com";
        if (userRepository.findByUsername(userName).isPresent()) {
            throw new IllegalArgumentException("User already exists");
        }
        UserEntity user = new UserEntity();
        user.setUsername(userName);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode("DefaultPass123!"));
        user.setActive(true);

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public UserEntity getUserById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Transactional
    public void deleteUserById(UUID id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalArgumentException("User not found");
        }
        userRepository.deleteById(id);
    }
}
