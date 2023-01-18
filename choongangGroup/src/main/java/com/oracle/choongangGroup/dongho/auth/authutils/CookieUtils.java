package com.oracle.choongangGroup.dongho.auth.authutils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class CookieUtils {
	private final HttpServletResponse httpResponse;
	
	
	// Request Header (cookie) 에서 keep토큰 정보 추출
    public String resolveKeepToken(HttpServletRequest request) {
    	Cookie[] list = request.getCookies();
        String bearerToken = "";
        if (list != null) {
        	for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("keepToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// 쿠키 value에서 bearer 부분 제외한 token만 추출
    		            return bearerToken.substring(6);
    		        }
    			}
    		}
		}
		return null;
	}

	// Request Header (cookie) 에서 access토큰 정보 추출
    public String resolveAccessToken(HttpServletRequest request) {
        Cookie[] list = request.getCookies();
        String bearerToken = "";
        if (list != null) {
        	for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("AccessToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// 쿠키 value에서 bearer 부분 제외한 token만 추출
    		            return bearerToken.substring(6);
    		        }
    			}
    		}
		}
		return null;
    }
    // Request Header (cookie) 에서 refresh토큰 정보 추출
    public String resolveRefreshToken(HttpServletRequest request) {
    	Cookie[] list = request.getCookies();
    	String bearerToken = "";
    	if (list != null) {
    		for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("RefreshToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// 쿠키 value에서 bearer 부분 제외한 token만 추출
    					return bearerToken.substring(6);
    				}
    			}
    		}
    	}
    	return null;
    }
    
    // httpOnly true -> javascript에 의한 토큰탈취 XSS공격 방지 (Cross Site Scripting)
    // http통신에서만 사용되게 하므로 클라이언트단 javascript(document.cookie)로 cookie정보 확인 불가
    // 유효시간을 정하지 않으면 session cookie (휘발성. 브라우저종료시 삭제)
    public void setCookie(String key, String token, boolean isRemember, boolean isDelCookie) {
    	if (isRemember) {
    		ResponseCookie cookie = ResponseCookie.from(key,"Bearer" + token)
            		.path("/")
            		.httpOnly(true)
            		.domain("localhost")
            		.maxAge(14 * 24 * 60 * 60)
            		.build();
    		httpResponse.addHeader("Set-Cookie", cookie.toString());
		} else {
	    	if (isDelCookie) {
	    		ResponseCookie cookie = ResponseCookie.from(key,"Bearer" + token)
	            		.path("/")
	            		.httpOnly(true)
	            		.domain("localhost")
	            		.maxAge(0) 
	            		.build();
	    		httpResponse.addHeader("Set-Cookie", cookie.toString());
			} else {
				ResponseCookie cookie = ResponseCookie.from(key,"Bearer" + token)
		        		.path("/")
		        		.httpOnly(true)
		        		.domain("localhost")
		        		.build();
				httpResponse.addHeader("Set-Cookie", cookie.toString());
			}
		}
    	

    }
    
}
