package com.example.librarymanagement.controllers;

import com.example.librarymanagement.entities.Book;
import com.example.librarymanagement.entities.Lending;
import com.example.librarymanagement.entities.User;
import com.example.librarymanagement.repositories.UserRepository;
import com.example.librarymanagement.services.BookService;
import com.example.librarymanagement.services.LendingService;
import com.example.librarymanagement.services.EmailService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Controller
public class UserDashboardController {

    @Autowired
    private BookService bookService;

    @Autowired
    private LendingService lendingService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    /**
     * Handles registration from the main landing page.
     * Prevents duplicate Username and Email crashes.
     */
    @PostMapping("/register")
    public String registerFromHome(@ModelAttribute("user") User user,
                                   HttpServletRequest request,
                                   Model model) {

        // 1. Check if Username is already taken
        User existingUserByUsername = userRepository.findByUsername(user.getUsername());
        if (existingUserByUsername != null) {
            return "redirect:/?error=userExists";
        }

        // 2. Check if Email is already taken (Fixes the SQL Error 2601)
        User existingUserByEmail = userRepository.findByEmail(user.getEmail());
        if (existingUserByEmail != null) {
            return "redirect:/?error=emailExists";
        }

        // 3. Prepare user data
        String rawPassword = user.getPassword(); // Keep raw for login
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole("USER");
        user.setRegistrationDate(LocalDate.now());

        // 4. Save to DB
        userRepository.save(user);

        // 5. Send Welcome Email
        try {
            if (user.getEmail() != null && !user.getEmail().isEmpty()) {
                emailService.sendWelcomeEmail(user.getEmail(), user.getUsername());
            }
        } catch (Exception e) {
            System.err.println("Email Error: " + e.getMessage());
        }

        // 6. AUTO-LOGIN: Redirect directly to Dashboard
        try {
            request.login(user.getUsername(), rawPassword);
            return "redirect:/user/dashboard";
        } catch (ServletException e) {
            return "redirect:/?registered=true";
        }
    }

    // --- DASHBOARD & HISTORY ---

    @GetMapping("/user/dashboard")
    public String userDashboard(@RequestParam(value = "keyword", required = false) String keyword,
                                Authentication authentication,
                                Model model) {
        String currentUsername = authentication.getName();
        List<Book> availableBooks;
        if (keyword != null && !keyword.trim().isEmpty()) {
            availableBooks = bookService.searchBooks(keyword);
        } else {
            availableBooks = bookService.getAvailableBooks();
        }
        model.addAttribute("books", availableBooks);
        model.addAttribute("keyword", keyword);
        model.addAttribute("username", currentUsername);
        return "user-dashboard";
    }

    @GetMapping("/user/history")
    public String userHistory(Authentication authentication, Model model) {
        String currentUsername = authentication.getName();
        List<Lending> myLendings = lendingService.findByUsername(currentUsername);
        model.addAttribute("myLendings", myLendings);
        model.addAttribute("username", currentUsername);
        return "user-history";
    }

    @PostMapping("/user/reserve")
    public String reserveBook(@RequestParam("bookId") Long id,
                              @RequestParam(value = "returnDate", required = false) String returnDate,
                              Authentication authentication) {

        Book book = bookService.getBookById(id);
        String currentUsername = authentication.getName();
        User user = userRepository.findByUsername(currentUsername);

        if (book != null && book.isAvailable() && user != null) {
            Lending newLending = new Lending();
            newLending.setBook(book);
            newLending.setUser(user);
            newLending.setBorrowerName(user.getUsername());
            newLending.setBorrowDate(LocalDate.now());

            if (returnDate != null && !returnDate.isEmpty()) {
                newLending.setReturnDate(LocalDate.parse(returnDate));
            } else {
                newLending.setReturnDate(LocalDate.now().plusDays(14));
            }

            newLending.setReturned(false);
            lendingService.saveLending(newLending);

            book.setAvailable(false);
            bookService.saveBook(book);
        }
        return "redirect:/user/history";
    }

    // --- ADMIN USER MANAGEMENT ---

    @GetMapping("/admin/users/add")
    public String showAddUserForm(Model model) {
        model.addAttribute("user", new User());
        return "add-user";
    }

    @PostMapping("/admin/users/save")
    public String saveUser(@ModelAttribute("user") User user, Model model) {
        // Checking uniqueness for Admin save as well
        if (userRepository.findByUsername(user.getUsername()) != null) {
            model.addAttribute("error", "Username ekziston!");
            return "add-user";
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);

        try {
            if (user.getEmail() != null && !user.getEmail().isEmpty()) {
                emailService.sendWelcomeEmail(user.getEmail(), user.getUsername());
            }
        } catch (Exception e) {
            System.err.println("Email Error: " + e.getMessage());
        }
        return "redirect:/admin/dashboard";
    }

    @PostMapping("/users/update")
    public String updateUser(@RequestParam("id") Long id,
                             @RequestParam("username") String username,
                             @RequestParam("role") String role,
                             @RequestParam(value = "expiryDate", required = false) String expiryDate) {

        Optional<User> userOpt = userRepository.findById(id);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setUsername(username);
            user.setRole(role);

            if (!"ADMIN".equals(role) && expiryDate != null && !expiryDate.isEmpty()) {
                user.setExpiryDate(LocalDate.parse(expiryDate));
            } else {
                user.setExpiryDate(null);
            }
            userRepository.save(user);
        }
        return "redirect:/admin/dashboard";
    }
}