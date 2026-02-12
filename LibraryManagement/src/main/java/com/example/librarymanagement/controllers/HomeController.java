package com.example.librarymanagement.controllers;

import com.example.librarymanagement.entities.User;
import com.example.librarymanagement.services.AuthorService;
import com.example.librarymanagement.services.BookService;
import com.example.librarymanagement.services.LendingService;
import com.example.librarymanagement.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Added for password security
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.time.LocalDate;

@Controller
public class HomeController {

    @Autowired
    private BookService bookService;

    @Autowired
    private AuthorService authorService;

    @Autowired
    private LendingService lendingService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder; // Injected from your SecurityConfig

    // 1. PUBLIC LANDING PAGE
    @GetMapping("/")
    public String landingPage(Model model) {
        model.addAttribute("user", new User());
        return "home";
    }

    // 3. PRIVATE ADMIN DASHBOARD
    @GetMapping("/dashboard")
    public String index(Model model) {
        model.addAttribute("totalBooks", bookService.countBooks());
        model.addAttribute("totalAuthors", authorService.countAuthors());
        model.addAttribute("activeLendings", lendingService.getActiveLendingsCount());
        model.addAttribute("totalUsers", userRepository.count());
        model.addAttribute("recentLendings", lendingService.getAllLendings());
        model.addAttribute("users", userRepository.findAll());
        return "index";
    }
}