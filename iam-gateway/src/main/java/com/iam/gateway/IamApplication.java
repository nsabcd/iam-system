package com.iam.gateway;

import com.iam.directory.model.ServicePrincipalEntity;
import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.ServicePrincipalRepository;
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
    CommandLineRunner initTestData(UserRepository userRepository, ServicePrincipalRepository servicePrincipalRepository){
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

            if(servicePrincipalRepository.findByClientId("test-service-client").isEmpty()){
                ServicePrincipalEntity entity = new ServicePrincipalEntity();
                entity.setClientId("test-service-client");
                entity.setClientSecretHash(encoder.encode("secret123"));
                entity.setServiceName("TestClientService");
                entity.setAllowedScopes("payments:read payments:write");
                servicePrincipalRepository.save(entity);
                System.out.println(">> Seeded test service principal: test-service-client / secret123");
            }
        };
    }


}
