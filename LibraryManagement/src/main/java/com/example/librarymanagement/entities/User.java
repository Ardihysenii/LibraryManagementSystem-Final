package com.example.librarymanagement.entities;

import jakarta.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true)
    private String email;

    private String role;

    private LocalDate registrationDate;
    private LocalDate expiryDate;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Lending> lendings;

    public User() {}

    @PrePersist
    protected void onCreate() {
        // Sets registration date automatically if not provided
        if (this.registrationDate == null) {
            this.registrationDate = LocalDate.now();
        }

        // Logic for Expiry Date based on Role
        // Matches "ADMIN" or "ROLE_ADMIN" to ensure it handles both formats
        if (this.role != null && (this.role.equals("ADMIN") || this.role.equals("ROLE_ADMIN"))) {
            this.expiryDate = null;
        } else if (this.expiryDate == null) {
            // Default 1 year expiry for standard users
            this.expiryDate = LocalDate.now().plusYears(1);
        }
    }

    // Getters and Setters (Kept exactly as yours)
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public LocalDate getRegistrationDate() { return registrationDate; }
    public void setRegistrationDate(LocalDate registrationDate) { this.registrationDate = registrationDate; }

    public LocalDate getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDate expiryDate) { this.expiryDate = expiryDate; }

    public List<Lending> getLendings() { return lendings; }
    public void setLendings(List<Lending> lendings) { this.lendings = lendings; }
}