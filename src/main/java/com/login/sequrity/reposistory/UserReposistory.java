package com.login.sequrity.reposistory;

import com.login.sequrity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserReposistory extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
