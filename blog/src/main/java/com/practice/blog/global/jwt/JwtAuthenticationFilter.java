package com.practice.blog.global.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    private final TokenProvider tokenProvider;

    private static final String BEARER = "Bearer ";
    private static final String HEADER = "Authorization";

    /**
     * JWT 인증 필터
     *
     * HTTP 요청을 가로채 JWT 토큰을 검사하고, 유효한 경우 인증 정보를 설정
     */
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 요청 헤더의 Authorization 키 값 조회
        String authorizationHeader = request.getHeader(HEADER);

        // Bearer 접두사를 제거하여 토큰 추출
        String token = getAccessToken(authorizationHeader);

        //토큰이 유효한 경우, 인증 정보를 설정(SecurityContext)에 인증정보 저장하여 해당 요청동안 인증된 사용자 정보를 받아올 수 있게 함
        if(!ObjectUtils.isEmpty(token) && tokenProvider.isValidToken(token)){
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        //다음 필터로 요청과 응답 전달
        filterChain.doFilter(request, response);
    }

    /**
     * Authorization 헤더에서 Bearer 접두사를 제거해 토큰 추출
     */
    private String getAccessToken(String authorizationHeader){
        // Token이 null이 아니고 Bearer로 시작해야지 정상적인 Token
        if(authorizationHeader != null && authorizationHeader.startsWith(BEARER)){
            // 정상적인 토큰이라면 앞에 Bearer 제거 후 리턴
            return authorizationHeader.substring(BEARER.length());
        }
        return null;
    }
}
