package com.iam.directory.repository;

import com.iam.directory.model.AuthorizationCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCodeEntity, UUID> {
    Optional<AuthorizationCodeEntity> findByCode(String code);
}
