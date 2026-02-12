package com.example.librarymanagement.controllers;

import com.example.librarymanagement.entities.Author;
import com.example.librarymanagement.services.AuthorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/authors")
public class AuthorController {

    @Autowired
    private AuthorService authorService;

    @GetMapping
    public String listAuthors(@RequestParam(value = "keyword", required = false) String keyword, Model model) {
        List<Author> authors;
        if (keyword != null && !keyword.isEmpty()) {
            authors = authorService.searchAuthors(keyword);
        } else {
            authors = authorService.getAllAuthors();
        }
        model.addAttribute("authors", authors);
        model.addAttribute("keyword", keyword);
        return "authors";
    }

    @GetMapping("/add")
    public String showAddForm(Model model) {
        model.addAttribute("author", new Author());
        return "Product/index";
    }

    @PostMapping("/save")
    public String saveAuthor(@Valid @ModelAttribute("author") Author author, BindingResult result) {
        if (result.hasErrors()) {
            return "Product/index";
        }
        authorService.saveAuthor(author);
        return "redirect:/authors";
    }

    @GetMapping("/edit/{id}")
    public String showEditForm(@PathVariable("id") Long id, Model model) {
        Author author = authorService.getAuthorById(id);
        if (author == null) return "redirect:/authors";
        model.addAttribute("author", author);
        return "Product/index";
    }

    @GetMapping("/delete/{id}")
    public String deleteAuthor(@PathVariable("id") Long id) {
        authorService.deleteAuthor(id);
        return "redirect:/authors";
    }
}