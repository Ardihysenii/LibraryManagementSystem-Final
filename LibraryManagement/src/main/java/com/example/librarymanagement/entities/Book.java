package com.example.librarymanagement.entities;

import com.example.librarymanagement.validations.UniqueISBN;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

@Entity
@Table(name = "books")
public class Book {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Titulli nuk mund të jetë i zbrazët")
    @Column(nullable = false)
    private String title;

    @UniqueISBN
    @NotBlank(message = "ISBN është i detyrueshëm")
    @Column(nullable = false, unique = true)
    private String isbn;

    private String genre;


    @Column(nullable = true)
    private Boolean available = true;

    @NotNull(message = "Duhet të zgjidhni një autor")
    @ManyToOne
    @JoinColumn(name = "author_id", nullable = false)
    private Author author;

    @OneToMany(mappedBy = "book", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Lending> lendings;

    public Book() {
        this.available = true;
    }

    public Book(String title, String isbn, String genre, Author author) {
        this.title = title;
        this.isbn = isbn;
        this.genre = genre;
        this.author = author;
        this.available = true;
    }


    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getIsbn() { return isbn; }
    public void setIsbn(String isbn) { this.isbn = isbn; }

    public String getGenre() { return genre; }
    public void setGenre(String genre) { this.genre = genre; }


    public boolean isAvailable() {
        return available == null || available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public Author getAuthor() { return author; }
    public void setAuthor(Author author) { this.author = author; }

    public List<Lending> getLendings() { return lendings; }
    public void setLendings(List<Lending> lendings) { this.lendings = lendings; }
}