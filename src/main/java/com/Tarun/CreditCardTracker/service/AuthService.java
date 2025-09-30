package com.Tarun.CreditCardTracker.service;

import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;

import com.Tarun.CreditCardTracker.model.Users;
import com.Tarun.CreditCardTracker.repository.UserRepository;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class AuthService {

    private final UserRepository userRepo;
    private final AuthenticationManager authManager;
    private final JavaMailSender mailSender;
    private final PasswordEncoder passwordEncoder;

    // OTP store keyed by email
    private final ConcurrentMap<String, String> otpStore = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> otpExpiry = new ConcurrentHashMap<>();
    private static final long OTP_TTL_MS = 2 * 60 * 1000L; // 2 minutes

    public AuthService(AuthenticationManager authManager,
                       UserRepository userRepo,
                       JavaMailSender mailSender,
                       JwtService jwtService,
                       PasswordEncoder passwordEncoder) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.mailSender = mailSender;
        this.passwordEncoder = passwordEncoder;
    }

    /** Clear stored OTPs older than TTL (optional housekeeping) */
    private void cleanExpiredOtps() {
        long now = System.currentTimeMillis();
        otpExpiry.forEach((email, expiry) -> {
            if (expiry < now) {
                otpExpiry.remove(email);
                otpStore.remove(email);
            }
        });
    }

   
    

    // --- Signup ---
    public String postSignup(String firstName, String lastName, String email, String phone,
                             String password, String confPassword, ModelMap map) {

        map.addAttribute("firstName", firstName);
        map.addAttribute("lastName", lastName);

        Users existingUser = userRepo.findByEmail(email);
        if (existingUser != null) map.addAttribute("validEmailError", "Email already present!");
        map.addAttribute("validEmail", email);

        Users existingPhone = userRepo.findByPhn(phone);
        boolean phonePresent = existingPhone != null;
        if (phonePresent) map.addAttribute("phnPresentError", "Mobile number already registered!");

        boolean validPhone = phone.matches("\\d{10}");
        if (!validPhone) map.addAttribute("validPhoneError", "Enter a valid phone number");
        else map.addAttribute("validPhone", phone);

        boolean validPassword = password.equals(confPassword);
        String validPasswordCriteria = passwordCriteria(password);
        
        if(phonePresent || existingUser!=null || !validPhone) {
        	return "auth/signup";
        }

        if (!validPassword) map.addAttribute("validPasswordError", "Passwords do not match");
        else if (!validPasswordCriteria.isEmpty())
            map.addAttribute("validPasswordCriteriaError", validPasswordCriteria);

        if (existingUser == null && validPhone && !phonePresent && validPassword && validPasswordCriteria.isEmpty()) {
            Users currUser = new Users();
            currUser.setFirstName(firstName);
            currUser.setLastName(lastName);
            currUser.setEmail(email);
            currUser.setPhn(phone);
            currUser.setPassword(passwordEncoder.encode(password)); // encode password

            userRepo.save(currUser);
            
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            return "pages/home";
        } else {
            return "auth/signup";
        }
    }

    // --- Password criteria check ---
    public String passwordCriteria(String password) {
        if (password.length() < 8) return "Password should contain at least 8 characters";
        int cap = 0, number = 0, symbol = 0;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) cap++;
            else if (Character.isDigit(c)) number++;
            else if (!Character.isLetterOrDigit(c)) symbol++;
        }
        if (cap == 0) return "Password should contain a capital letter";
        if (number == 0) return "Password should contain a number";
        if (symbol == 0) return "Password should contain a special character";
        return "";
    }

    // --- Generate OTP ---
    public String postGenerateOTP(String email, ModelMap map) throws MessagingException {
        cleanExpiredOtps();
        Users user = userRepo.findByEmail(email);
        map.addAttribute("email", email);

        if (user == null) {
            map.addAttribute("emailNotPresentError", "Email is not registered!");
            map.addAttribute("otpSent", false);
            return "auth/forgotPassword";
        } else {
            String otp = String.valueOf(100000 + new Random().nextInt(900000));
            otpStore.put(email, otp);
            otpExpiry.put(email, System.currentTimeMillis() + OTP_TTL_MS);

            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, false, "UTF-8");

            String content =
                    "<p>Dear " + user.getFirstName() + " " + user.getLastName() + ",</p>" +
                            "<p><strong>This email was sent in response to your \"Forgot Password\" request.</strong> Generated OTP is valid for 2 minutes.</p>" +
                            "If you DID NOT make the request, you may disregard this email." +
                            "<p><strong>OTP:</strong> " + otp + "</p>" +
                            "<p>Thank You<br/>Credit Tracker</p>";

            helper.setTo(email);
            helper.setSubject("Requested OTP From Credit Tracker");
            helper.setText(content, true);

            try {
                mailSender.send(msg);
            } catch (MailException ex) {
                map.addAttribute("otpSent", false);
                map.addAttribute("emailError", "Failed to send OTP. Try again later.");
                return "auth/forgotPassword";
            }

            map.addAttribute("otpMessage", "Enter the OTP sent to your registered email.");
            return "auth/forgotPassword";
        }
    }

    // --- Validate OTP ---
    public String postValidateOTP(String email, String otp1, String otp2, String otp3,
                                  String otp4, String otp5, String otp6, ModelMap map) {
        cleanExpiredOtps();
        map.addAttribute("email",email);
        String inputOtp = String.join("",
                otp1 == null ? "" : otp1.trim(),
                otp2 == null ? "" : otp2.trim(),
                otp3 == null ? "" : otp3.trim(),
                otp4 == null ? "" : otp4.trim(),
                otp5 == null ? "" : otp5.trim(),
                otp6 == null ? "" : otp6.trim());

        if (!inputOtp.matches("\\d{6}")) {
            map.addAttribute("otpMessageError", "Enter a 6-digit OTP");
            return "auth/forgotPassword";
        }

        String storedOtp = otpStore.get(email);
        Long expiry = otpExpiry.get(email);
        
        if(expiry>=System.currentTimeMillis()) {
        	map.addAttribute("otpTimeout","OTP expired. Please request a new OTP.");
        	return "auth/forgotPassword";
        }

        if (storedOtp != null && expiry != null && expiry >= System.currentTimeMillis() && storedOtp.equals(inputOtp)) {
            // valid -> remove from store
            otpStore.remove(email);
            otpExpiry.remove(email);
            // pass email to reset page as hidden field or session
            map.addAttribute("email", email);
            return "auth/resetPassword";
        } else {
            map.addAttribute("otpMessageError", "Invalid OTP");
            return "auth/forgotPassword";
        }
    }

    // --- Reset password ---
    public String postResetPassword(String email, String password, String confirmPassword, ModelMap map) {
        boolean validPassword = password.equals(confirmPassword);
        String validPasswordCriteria = passwordCriteria(password);

        if (!validPassword) map.addAttribute("validPasswordError", "Passwords do not match");
        else if (!validPasswordCriteria.isEmpty())
            map.addAttribute("validPasswordCriteriaError", validPasswordCriteria);

        if (validPassword && validPasswordCriteria.isEmpty()) {
            Users user = userRepo.findByEmail(email);
            if (user != null) {
                user.setPassword(passwordEncoder.encode(password));
                userRepo.save(user);
            }
            return "auth/login";
        } else {
            map.addAttribute("email", email);
            return "auth/resetPassword";
        }
    }
}
