package com.iam.gateway;

import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication(scanBasePackages = "com.iam")
@EnableJpaRepositories(basePackages = "com.iam.directory.repository")
@EntityScan(basePackages = "com.iam.directory.model")
public class IamApplication {
    public static void main(String[] args) {
        SpringApplication.run(IamApplication.class, args);
    }

    @Bean
    CommandLineRunner initTestData(UserRepository userRepository){
        return args -> {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            if(userRepository.findByUsername("testuser").isEmpty()){
                UserEntity user = new UserEntity();
                user.setUsername("testuser");
                user.setEmail("testuser@iam.com");
                user.setPasswordHash(encoder.encode("password123"));
                userRepository.save(user);
                System.out.println(">> Seeded test user: testuser / password123");
            }
        };
    }

}
