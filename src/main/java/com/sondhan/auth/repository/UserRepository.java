package com.sondhan.auth.repository;

import com.sondhan.auth.domain.PiiToken;
import com.sondhan.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByPhoneToken(PiiToken phoneToken);

    @Query("SELECT u FROM User u WHERE u.phoneToken.id = :tokenId")
    Optional<User> findByPhoneTokenId(@Param("tokenId") UUID tokenId);

    boolean existsByPhoneToken(PiiToken phoneToken);

    boolean existsByEmailToken(PiiToken emailToken);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.active = false WHERE u.id = :userId")
    void deactivateUser(@Param("userId") UUID userId);
}
