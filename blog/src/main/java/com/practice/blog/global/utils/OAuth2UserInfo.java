package com.practice.blog.global.utils;

import java.util.Map;

// 구글에서 제공하는 사용자정보를 다루기 위한 유틸리티 클래스
// 사용자 정보를 담은 attributes를 받아와 이를 통해 특정한 사용자 정보를 반환하는 역할을 한다.
public class OAuth2UserInfo{

    private final Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public String getNickname() {
        return (String) attributes.get("nickname");
    }

    public String getEmail() {
        return (String) attributes.get("email");
    }

}
