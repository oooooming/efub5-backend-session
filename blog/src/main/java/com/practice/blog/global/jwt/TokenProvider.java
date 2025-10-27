package com.practice.blog.global.jwt;

import com.practice.blog.account.entity.Account;
import com.practice.blog.account.repository.AccountsRepository;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenProvider {

    // application.yml에 저장한 jwt값 가져오기
    @Value("${jwt.secretKey}")
    private String secretKey;

    // 토큰 만료시간 설정
    private static Long accessTokenExpiration = 1000*60*60L;
    private static Long refreshTokenExpiration = 1000*60*60*25*14L;

    // 토큰에 포함할 기본 정보와 클레임 키값 설정
    private static final String AUTH_CLAIM = "auth";

    private final AccountsRepository accountsRepository;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * AccessToken 생성 메소드
     * 사용자 이메일 정보를 포함해 AccessToken 생성
     */
    public String createAccessToken(Account account) {
        Date now = new Date();
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + accessTokenExpiration))
                .setSubject(account.getEmail())
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * RefreshToken 생성 메소드
     */
    public String createRefreshToken(Account account) {
        Date now = new Date();
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + refreshTokenExpiration))
                .setSubject(account.getEmail())
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * Redis에 리프레시 토큰을 저장하는 메소드
     * key: 사용자 ID, alue: 리프레시 토큰
     * 리프레시토큰 만료 시간(refreshTokenExpiration)을 만료시간으로 정해 자동으로 삭제되도록 설정
     */
    public void saveRefreshToken(Long userId, String refreshToken) {
        redisTemplate.opsForValue().set(userId.toString(), refreshToken, Duration.ofMillis(refreshTokenExpiration));
    }

    /**
     * AccessToken에서 email 추출
     * 토큰이 유효한지 확인 후 이메일 클레임 값을 추출
     */
    public String extractEmail(String accessToken){
        if(isValidToken(accessToken)){
            return getClaims(accessToken).getSubject();
        }
        return null;
    }

    /**
     * 유효한 토큰인지 검증
     */
    public boolean isValidToken(String token){
        try{
            // secretKey를 사용해 토큰 복호화
            Jwts.parser()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            log.info("Validate token success");
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty", e);
        }
        return false;
    }

    /**
     * 토큰에서 사용자 인증 정보를 꺼내 반환
     * JWT 토큰의 클레임에서 사용자 이메일과 권한 정보를 추출하여 Authentication 객체를 생성
     */
    public Authentication getAuthentication(String token){
        // 토큰 복호화
        Claims claims = getClaims(token);

        // 토큰에서 정보를 꺼냄
        Set<SimpleGrantedAuthority> authorities = Collections
                .singleton(new SimpleGrantedAuthority("ROLE_USER"));

        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails
                .User(claims.getSubject(), "", authorities), token, authorities);
    }

    /**
     * 토큰을 복호화한 후 페이로드 반환
     */
    private Claims getClaims(String token){
        return Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getPayload();
    }
}
