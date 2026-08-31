package com.iam.directory.repository;

import com.iam.directory.model.ServicePrincipalEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ServicePrincipalRepository extends JpaRepository<ServicePrincipalEntity, UUID> {
    Optional<ServicePrincipalEntity> findByClientId(String clientId);
}
