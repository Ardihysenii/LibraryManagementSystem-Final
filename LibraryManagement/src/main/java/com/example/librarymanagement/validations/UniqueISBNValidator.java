package com.example.librarymanagement.validations;

import com.example.librarymanagement.entities.Book;
import com.example.librarymanagement.repositories.BookRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.util.Optional;

public class UniqueISBNValidator implements ConstraintValidator<UniqueISBN, String> {

    @Autowired
    private BookRepository bookRepository;

    @Autowired(required = false)
    private HttpServletRequest request;

    @Override
    public void initialize(UniqueISBN constraintAnnotation) {

        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
    }

    @Override
    public boolean isValid(String isbn, ConstraintValidatorContext context) {
        if (isbn == null || isbn.isEmpty()) return true;


        if (bookRepository == null && request != null) {
            ApplicationContext appContext = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(request.getServletContext());
            bookRepository = appContext.getBean(BookRepository.class);
        }

        if (bookRepository == null) return true;

        Optional<Book> bookInDb = bookRepository.findByIsbn(isbn);
        if (bookInDb.isEmpty()) return true;

        if (request != null) {
            try {
                String idParam = request.getParameter("id");
                if (idParam != null && !idParam.isEmpty()) {
                    Long currentId = Long.parseLong(idParam);
                    if (bookInDb.get().getId().equals(currentId)) {
                        return true;
                    }
                }
            } catch (Exception e) {

            }
        }

        return false;
    }
}