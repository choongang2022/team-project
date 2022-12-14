package com.oracle.choongangGroup.dongho.auth;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.HandlerInterceptor;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RsaInterceptor implements HandlerInterceptor {
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		log.info("===RsaInterceptor preHandle start===");
//		if (request.getAttribute("publicKeyModulus") != "" && request.getAttribute("publicKeyExponent") != "") {
//			return true;
//		}
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        
        KeyPair    keyPair = generator.genKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        PublicKey  publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        HttpSession session = request.getSession();
        session.setAttribute("__rsaPrivateKey__", privateKey);
        
        RSAPublicKeySpec publicKeySpec = keyFactory.<RSAPublicKeySpec>getKeySpec(publicKey, RSAPublicKeySpec.class);
        
        String publicKeyModulus  = publicKeySpec.getModulus().toString(16);
        String publicKeyExponent = publicKeySpec.getPublicExponent().toString(16);
        log.info("RsaInterceptor publicKeyModulus : {} ", publicKeyModulus);
        log.info("RsaInterceptor publicKeyExponent : {} ", publicKeyExponent);
        request.setAttribute("publicKeyModulus" , publicKeyModulus);
        request.setAttribute("publicKeyExponent", publicKeyExponent);
        return true;
	}
}
