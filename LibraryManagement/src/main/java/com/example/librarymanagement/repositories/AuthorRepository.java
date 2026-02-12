package com.example.librarymanagement.repositories;

import com.example.librarymanagement.entities.Author;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AuthorRepository extends JpaRepository<Author, Long> {


    List<Author> findByNameContainingIgnoreCaseOrNationalityContainingIgnoreCase(String name, String nationality);
}