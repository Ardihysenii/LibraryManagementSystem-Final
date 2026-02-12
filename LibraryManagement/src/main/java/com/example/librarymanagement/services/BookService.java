package com.example.librarymanagement.services;

import com.example.librarymanagement.entities.Book;
import com.example.librarymanagement.repositories.BookRepository;
import com.example.librarymanagement.entities.Lending;
import com.example.librarymanagement.repositories.LendingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class BookService {
    @Autowired
    private BookRepository bookRepository;

    @Autowired
    private LendingRepository lendingRepository;


    public List<Book> findAll() {
        return bookRepository.findAll();
    }

    public long countBooks() {
        return bookRepository.count();
    }

    public List<Book> getAllBooks() {
        return bookRepository.findAll();
    }

    public List<Book> getAvailableBooks() {

        List<Long> rentedBookIds = lendingRepository.findByReturnedFalse()
                .stream()
                .map(lending -> lending.getBook().getId())
                .collect(Collectors.toList());

        return bookRepository.findAll().stream()
                .filter(book -> !rentedBookIds.contains(book.getId()))
                .collect(Collectors.toList());
    }

    public Book getBookById(Long id) {
        return bookRepository.findById(id).orElse(null);
    }

    public void saveBook(Book book) {
        bookRepository.save(book);
    }

    public void deleteBook(Long id) {
        bookRepository.deleteById(id);
    }

    public List<Book> searchBooks(String keyword) {
        return bookRepository.findByTitleContainingIgnoreCaseOrIsbnContainingIgnoreCase(keyword, keyword);
    }
}