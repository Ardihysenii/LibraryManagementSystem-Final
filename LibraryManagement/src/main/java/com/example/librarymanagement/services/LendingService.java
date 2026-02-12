package com.example.librarymanagement.services;

import com.example.librarymanagement.entities.Book;
import com.example.librarymanagement.entities.Lending;
import com.example.librarymanagement.entities.User;
import com.example.librarymanagement.repositories.BookRepository;
import com.example.librarymanagement.repositories.LendingRepository;
import com.example.librarymanagement.repositories.UserRepository; // Nevojitet për të gjetur User-in
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Service
public class LendingService {

    @Autowired
    private LendingRepository lendingRepository;

    @Autowired
    private BookRepository bookRepository;

    @Autowired
    private UserRepository userRepository;


    @Transactional
    public void returnBook(Long lendingId) {
        Lending lending = lendingRepository.findById(lendingId).orElse(null);

        if (lending != null && !lending.isReturned()) {
            lending.setReturned(true);
            lending.setActualReturnDate(LocalDate.now());

            Book book = lending.getBook();
            if (book != null) {
                book.setAvailable(true);
                bookRepository.save(book);
            }
            lendingRepository.save(lending);
        }
    }



    public List<Lending> getAllLendings() {
        return lendingRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
    }

    public List<Lending> findByUsername(String username) {
        return lendingRepository.findByUserUsername(username);
    }

    public List<Lending> findAllByUserId(Long userId) {
        return lendingRepository.findByUserId(userId);
    }

    public List<Lending> searchByBorrower(String keyword) {
        return lendingRepository.findByBorrowerNameContainingIgnoreCase(keyword);
    }


    public void saveLending(Lending lending) {

        if (lending.getUser() == null && lending.getBorrowerName() != null) {
            User user = userRepository.findByUsername(lending.getBorrowerName());
            if (user != null) {
                lending.setUser(user);
            }
        }
        lendingRepository.save(lending);
    }

    public void deleteLending(Long id) {
        lendingRepository.deleteById(id);
    }

    public Lending getLendingById(Long id) {
        return lendingRepository.findById(id).orElse(null);
    }

    public long getActiveLendingsCount() {
        return lendingRepository.countByReturnedFalse();
    }

    public boolean isBookAvailable(Long bookId) {
        return !lendingRepository.existsByBookIdAndReturnedFalse(bookId);
    }
}