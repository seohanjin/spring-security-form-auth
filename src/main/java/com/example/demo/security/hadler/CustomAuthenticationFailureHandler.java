package com.example.demo.security.hadler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "아이디 혹은 비밀번호가 틀립니다.";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "아이디 혹은 비밀번호가 틀립니다.";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "추가 파라미터가 틀립니다.";
        }

        // 한글은 인코딩하지 않으면 controller 로 가지 않음.
        errorMessage = URLEncoder.encode(errorMessage, "UTF-8");
        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

        super.onAuthenticationFailure(request, response, exception);
    }
}
