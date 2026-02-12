package com.example.librarymanagement.repositories;

import com.example.librarymanagement.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Existing method
    User findByUsername(String username);

    // NEW: Added to prevent the Duplicate Key SQL error
    User findByEmail(String email);

    // Existing method
    List<User> findAllByOrderByIdDesc();
}