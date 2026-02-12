package com.example.librarymanagement.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendWelcomeEmail(String toEmail, String username) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("emaili_yt@gmail.com");
        message.setTo(toEmail);
        message.setSubject("Mirësevini në LIBRA CORE!");
        message.setText("Përshëndetje " + username + ",\n\n" +
                "Llogaria juaj në sistemin e bibliotekës LIBRA CORE u krijua me sukses.\n" +
                "Tani mund të hyni dhe të rezervoni librat tuaj të preferuar.\n\n" +
                "Me respekt,\nStafi i Bibliotekës.");

        mailSender.send(message);
    }
}