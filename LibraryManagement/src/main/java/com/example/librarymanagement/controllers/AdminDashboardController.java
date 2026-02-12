package com.example.librarymanagement.controllers;

import com.example.librarymanagement.entities.User;
import com.example.librarymanagement.repositories.UserRepository;
import com.example.librarymanagement.services.BookService;
import com.example.librarymanagement.services.LendingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@Controller
public class AdminDashboardController {

    @Autowired
    private BookService bookService;

    @Autowired
    private LendingService lendingService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/admin/dashboard")
    public String adminDashboard(Model model) {
        List<User> listUsers = userRepository.findAllByOrderByIdDesc();
        model.addAttribute("users", listUsers);
        model.addAttribute("totalUsers", listUsers.size());
        model.addAttribute("totalBooks", bookService.countBooks());
        model.addAttribute("totalLendings", lendingService.getAllLendings().size());
        model.addAttribute("books", bookService.getAllBooks());
        return "admin-dashboard";
    }

    @GetMapping("/users/add")
    public String showAddUserForm(Model model) {
        model.addAttribute("user", new User());
        return "add-user";
    }

    @PostMapping("/users/save")
    public String saveUser(@ModelAttribute("user") User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        LocalDate today = LocalDate.now();
        user.setRegistrationDate(today);
        if ("ADMIN".equals(user.getRole())) {
            user.setExpiryDate(today.plusYears(100));
        } else {
            user.setExpiryDate(today.plusMonths(1));
        }
        userRepository.save(user);
        return "redirect:/admin/dashboard";
    }


    @GetMapping("/users/edit/{id}")
    public String showEditForm(@PathVariable("id") Long id, Model model) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("ID e gabuar:" + id));
        model.addAttribute("user", user);
        return "edit-user";
    }

    @PostMapping("/users/update/{id}")
    public String updateUser(@PathVariable("id") Long id, @ModelAttribute("user") User user) {
        User existingUser = userRepository.findById(id).orElseThrow();
        existingUser.setUsername(user.getUsername());
        existingUser.setRole(user.getRole());
        existingUser.setExpiryDate(user.getExpiryDate());

        userRepository.save(existingUser);
        return "redirect:/admin/dashboard";
    }


    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userRepository.deleteById(id);
        return "redirect:/admin/dashboard";
    }
}