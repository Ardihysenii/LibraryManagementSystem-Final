package com.example.librarymanagement.repositories;

import com.example.librarymanagement.entities.Lending;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface LendingRepository extends JpaRepository<Lending, Long> {


    @Query("SELECT l FROM Lending l WHERE l.user.username = :username ORDER BY l.id DESC")
    List<Lending> findByUserUsername(@Param("username") String username);


    @Query("SELECT l FROM Lending l WHERE l.user.id = :userId ORDER BY l.id DESC")
    List<Lending> findByUserId(@Param("userId") Long userId);


    @Query("SELECT l FROM Lending l WHERE LOWER(l.borrowerName) LIKE LOWER(CONCAT('%', :borrowerName, '%')) ORDER BY l.id DESC")
    List<Lending> findByBorrowerNameContainingIgnoreCase(@Param("borrowerName") String borrowerName);


    List<Lending> findByReturnedFalse();
    long countByReturnedFalse();


    boolean existsByBookIdAndReturnedFalse(Long bookId);
}