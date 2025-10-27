package com.practice.blog.global.handler;

import com.practice.blog.account.repository.AccountsRepository;
import com.practice.blog.account.entity.Account;
import com.practice.blog.global.jwt.TokenProvider;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AccountsRepository accountsRepository;
    private final TokenProvider tokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttributes().get("email");

        Account account = accountsRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("해당 email을 가진 Account를 찾을 수 없습니다. email: " + email));

        String accessToken = tokenProvider.createAccessToken(account);
        String refreshToken = tokenProvider.createRefreshToken(account);

        tokenProvider.saveRefreshToken(account.getAccountId(), refreshToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String jsonResponse = String.format("{\"access_token\":\"%s\", \"refresh_token\":\"%s\"}", accessToken, refreshToken);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();

        log.info("OAuth2 로그인 성공 - email: {}, accessToken 발급 완료", email);
    }
}
