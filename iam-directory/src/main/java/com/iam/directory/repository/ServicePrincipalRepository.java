package com.iam.directory.repository;

import com.iam.directory.model.ServicePrincipalEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ServicePrincipalRepository extends JpaRepository<ServicePrincipalEntity, UUID> {
    Optional<ServicePrincipalEntity> findByClientId(String clientId);
}
