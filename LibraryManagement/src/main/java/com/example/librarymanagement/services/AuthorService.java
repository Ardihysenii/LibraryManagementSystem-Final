package com.example.librarymanagement.services;

import com.example.librarymanagement.entities.Author;
import com.example.librarymanagement.repositories.AuthorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class AuthorService {

    @Autowired
    private AuthorRepository authorRepository;


    public long countAuthors() {
        return authorRepository.count();
    }

    public List<Author> getAllAuthors() {
        return authorRepository.findAll();
    }

    public Author getAuthorById(Long id) {
        return authorRepository.findById(id).orElse(null);
    }

    public void saveAuthor(Author author) {
        authorRepository.save(author);
    }

    public void deleteAuthor(Long id) {
        authorRepository.deleteById(id);
    }

    public List<Author> searchAuthors(String keyword) {
        return authorRepository.findByNameContainingIgnoreCaseOrNationalityContainingIgnoreCase(keyword, keyword);
    }
}