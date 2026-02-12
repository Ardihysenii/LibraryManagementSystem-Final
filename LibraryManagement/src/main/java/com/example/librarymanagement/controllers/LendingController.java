package com.example.librarymanagement.controllers;

import com.example.librarymanagement.entities.Book;
import com.example.librarymanagement.entities.Lending;
import com.example.librarymanagement.entities.User;
import com.example.librarymanagement.repositories.UserRepository;
import com.example.librarymanagement.services.LendingService;
import com.example.librarymanagement.services.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/lendings")
public class LendingController {

    @Autowired
    private LendingService lendingService;

    @Autowired
    private BookService bookService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public String listLendings(@RequestParam(value = "keyword", required = false) String keyword, Model model) {
        try {
            prepareModel(model, keyword);
            return "lendings";
        } catch (Exception e) {
            // Logimi i errorit ndihmon me gjet ku osht problemi n'konzolë
            System.out.println("Error te listLendings: " + e.getMessage());
            return "redirect:/"; // Në rast errori ekstrem, t'kthe te dashboard
        }
    }

    private void prepareModel(Model model, String keyword) {
        List<Lending> lendings;
        if (keyword != null && !keyword.trim().isEmpty()) {
            lendings = lendingService.searchByBorrower(keyword);
        } else {
            lendings = lendingService.getAllLendings();
        }

        // RREGULLIMI: Sigurohemi që nuk dështon kërkimi i userave
        List<User> allUsers;
        try {
            allUsers = userRepository.findAll(Sort.by(Sort.Direction.ASC, "username"));
        } catch (Exception e) {
            allUsers = new ArrayList<>(); // Nëse dështon renditja, kthe listë boshe
        }

        Lending newLending = new Lending();
        newLending.setBorrowDate(LocalDate.now());
        newLending.setReturnDate(LocalDate.now().plusDays(14));

        model.addAttribute("lending", newLending);
        model.addAttribute("lendings", (lendings != null) ? lendings : new ArrayList<>());
        model.addAttribute("books", bookService.getAvailableBooks());
        model.addAttribute("users", allUsers);
        model.addAttribute("keyword", keyword);
    }

    @PostMapping("/save")
    public String saveLending(@ModelAttribute("lending") Lending lending) {
        lending.setReturned(false);

        if (lending.getBook() != null && lending.getBook().getId() != null) {
            Book book = bookService.getBookById(lending.getBook().getId());
            if (book != null) {
                lending.setBook(book);
                book.setAvailable(false);
                bookService.saveBook(book);
            }
        }
        lendingService.saveLending(lending);
        return "redirect:/lendings";
    }

    @PostMapping("/return/{id}")
    public String markAsReturned(@PathVariable("id") Long id) {
        Lending lending = lendingService.getLendingById(id);
        if (lending != null) {
            lending.setReturned(true);
            lending.setActualReturnDate(LocalDate.now());

            Book book = lending.getBook();
            if (book != null) {
                book.setAvailable(true);
                bookService.saveBook(book);
            }
            lendingService.saveLending(lending);
        }
        return "redirect:/lendings";
    }
}