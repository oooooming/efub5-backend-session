package com.practice.blog.account.service;

import com.practice.blog.account.dto.response.TokenResponseDto;
import com.practice.blog.account.entity.Account;
import com.practice.blog.account.repository.AccountsRepository;
import com.practice.blog.global.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {
    private final AccountsRepository accountsRepository;
    private final TokenProvider tokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * AccessToken 재발급
     *
     * 클라이언트가 전달한 리프레시 토큰을 검증해 유효한 경우 새로운 액세스토큰을 발급한다.
     */
    public TokenResponseDto reissueAccessToken(String refreshToken){

        //전달받은 리프레시 토큰에서 이메일을 추출하여 사용자 정보 가져오기
        String email = tokenProvider.extractEmail(refreshToken);
        Account account = getUserByEmail(email);

        // Redis에서 해당 사용자 Id를 키로 하는 리프래시 토큰 가져오기
        String storedRefreshToken = redisTemplate.opsForValue().get(account.getAccountId().toString());

        //전달받은 리프레시 토큰과 Redis에 저장된 리프레시 토큰이 일하는지 확인
        if(storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)){
            throw new IllegalArgumentException("유효하지 않은 리 프레시 토큰입니다.");
        }

        //일치한다면 새로운 AccessToken 생성
        String accessToken = tokenProvider.createAccessToken(account);

        return TokenResponseDto.builder()
                .accessToken(accessToken)
                .build();
    }

    /**
     * Email로 사용자 객체 가져오기
     */
    @Transactional(readOnly = true)
    public Account getUserByEmail(String email){
        return accountsRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("해당 이메일로 사용자를 찾을 수 없습니다."));
    }

}
