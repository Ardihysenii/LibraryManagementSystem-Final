package com.example.librarymanagement.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UniqueISBNValidator.class)
@Documented
public @interface UniqueISBN {
    String message() default "Ky ISBN ekziston një herë në sistem!";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}