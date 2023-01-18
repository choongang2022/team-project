	package com.oracle.choongangGroup.dongho.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import com.oracle.choongangGroup.dongho.auth.authutils.CookieUtils;

import io.jsonwebtoken.Claims;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;
    private final SecurityService securityService;
    private final HttpServletResponse httpResponse;
    private final CookieUtils cookieUtils;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
    	log.info("====JwtAuthenticationFilter Start====");
        // Request Header cookie 에서 JWT 토큰 추출
		String accessToken  = cookieUtils.resolveAccessToken((HttpServletRequest) request);
		String refreshToken = cookieUtils.resolveRefreshToken((HttpServletRequest) request);
		String keepToken    = cookieUtils.resolveKeepToken((HttpServletRequest) request);
          
        boolean validateKeepToken = jwtTokenProvider.validateToken(keepToken);
        log.info("KeepToken 유효성 검사 결과 : {}", validateKeepToken);
        boolean validateAccessToken = jwtTokenProvider.validateToken(accessToken);
        log.info("AccessToken 유효성 검사 결과 : {}", validateAccessToken);
        boolean validateRefreshToken = jwtTokenProvider.validateToken(refreshToken);
        log.info("RefreshToken 유효성 검사 결과 : {}", validateRefreshToken);
        // 토큰 상태에 따라 로직 수행
        // validateToken 으로 토큰 유효성 검사
        // 자동 로그인 경우 토큰 유효성 검사
        if(keepToken != null && validateKeepToken) {
        	if(validateAccessToken && validateRefreshToken) {
        		log.info("===keep validateToken1 start===");
                // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext 에 저장
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                log.info("jwtTokenProvider.getAuthentication : {}", authentication.getName());
                SecurityContextHolder.getContext().setAuthentication(authentication);

        	}  else if (!validateAccessToken && refreshToken != null) {
            	log.info("===keep validateToken2 start===");
            	log.info("====keep accessToken 만료, refreshToken 유효성 검사 시작====");
            	// AT로부터 memberId 받기
            	Claims claims = jwtTokenProvider.parseClaims(accessToken);
            	String userid = claims.getSubject();
            	log.info("validateToken2 userid : {}", userid);
            	// AT로부터 authentication 객체 받기
            	Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            	log.info("keep validateToken2 getAuthentication Done");
            	// RT db에 있는 RT 와 일치하는지 검사
            	boolean equalRefreshToken = jwtTokenProvider.existsRefreshToken(refreshToken , userid);
            	log.info("keep validateToken2 RefreshToken DB값 일치 : {}", equalRefreshToken);
            	
            	// RT가 만료되지 않고 DB RT 와 일치하는 경우
            	if (validateRefreshToken && equalRefreshToken) {
            		log.info("===keep validateRefreshToken && equalRefreshToken start===");
            		log.info("===keep AccessToken 만료, RefreshToken 유효하므로 토큰 재발급===");
            		setTokensAndCookies(authentication, userid);
            		
    			}
            	else if(!validateAccessToken && !validateRefreshToken) {
            		log.info("====keepToken 유효, AT,RT 재발급 시작====");
                	// KT로부터 memberId 받기
                	claims = jwtTokenProvider.parseClaims(keepToken);
                	userid = claims.getSubject();
                	log.info("validateKeepToken userid : {}", userid);
                	// KT로부터 authentication 객체 받기
                	authentication = jwtTokenProvider.getAuthentication(keepToken);
                	log.info("validateKeepToken getAuthentication Done");
                	setTokensAndCookies(authentication, userid);
            		
            	}
        	} else if (!validateAccessToken && !validateRefreshToken) {
        		log.info("====keepToken 유효, AT,RT 재발급 시작====");
            	// KT로부터 memberId 받기
            	Claims claims = jwtTokenProvider.parseClaims(keepToken);
            	String userid = claims.getSubject();
            	log.info("validateKeepToken userid : {}", userid);
            	// KT로부터 authentication 객체 받기
            	Authentication authentication = jwtTokenProvider.getAuthentication(keepToken);
            	log.info("validateKeepToken getAuthentication Done");
            	setTokensAndCookies(authentication, userid);
        	}
        	
        // keepToken 없는 경우 (일반 로그인)	
        } else {
        	if (accessToken != null && validateAccessToken) {
            	log.info("===validateToken1 start===");
                // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가지고 와서 SecurityContext 에 저장
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                log.info("jwtTokenProvider.getAuthentication : {}", authentication.getName());
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // AT 유효기간 지나고 RT가 null이 아니면 RT 검증후 AT,RT 재발급
            } else if (accessToken != null && !validateAccessToken && refreshToken != null) {
            	log.info("===validateToken2 start===");
            	log.info("====accessToken 만료, refreshToken 유효성 검사 시작====");
            	// AT로부터 memberId 받기
            	Claims claims = jwtTokenProvider.parseClaims(accessToken);
            	String userid = claims.getSubject();
            	log.info("validateToken2 userid : {}", userid);
            	// AT로부터 authentication 객체 받기
            	Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            	log.info("validateToken2 getAuthentication Done");
            	// RT db에 있는 RT 와 일치하는지 검사
            	boolean equalRefreshToken = jwtTokenProvider.existsRefreshToken(refreshToken , userid);
            	log.info("validateToken2 RefreshToken DB값 일치 : {}", equalRefreshToken);
            	
            	// RT가 만료되지 않고 DB RT 와 일치하는 경우
            	if (validateRefreshToken && equalRefreshToken) {
            		log.info("===validateRefreshToken && equalRefreshToken start===");
            		log.info("===AccessToken 만료, RefreshToken 유효하므로 토큰 재발급===");
            		setTokensAndCookies(authentication, userid);

    			} else if(!validateAccessToken && !validateRefreshToken) {
    				log.info("======AccessToken ,refreshToken 만료! 토큰쿠키 삭제! ======");
    				cookieUtils.setCookie("AccessToken", "deleteToken", false, true);
    		        cookieUtils.setCookie("RefreshToken", "deleteToken", false, true);
    			}
            }
        }
        chain.doFilter(request, response);
    }
    
    // 토큰 생성 , 쿠키 생성 method
    private void setTokensAndCookies(Authentication authentication, String userid) throws UnsupportedEncodingException {
    	// 새 AT, RT 생성
		TokenInfo newTokenInfo = jwtTokenProvider.generateToken(authentication);
		String newAT = URLEncoder.encode(newTokenInfo.getAccessToken(), "utf-8");
        String newRT = URLEncoder.encode(newTokenInfo.getRefreshToken(), "utf-8");
        // AT로부터 authentication 객체 받기
        Authentication newAuthentication = jwtTokenProvider.getAuthentication(newAT);
        // 새로운 토큰에서 Authentication 객체를 가지고 와서 SecurityContext 에 저장
        SecurityContextHolder.getContext().setAuthentication(newAuthentication);
        // 새 RT DB에 저장
        securityService.saveRefreshToken(newRT, userid);
        
        // 쿠키에 새로운 AT , RT 저장
        cookieUtils.setCookie("AccessToken", newAT, false, false);
        cookieUtils.setCookie("RefreshToken", newRT, false, false);
    }
}
