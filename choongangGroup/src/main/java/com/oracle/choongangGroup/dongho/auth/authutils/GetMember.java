package com.oracle.choongangGroup.dongho.auth.authutils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.SecurityService;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class GetMember {
	private final SecurityService securityService;
	public Member getMember() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = authentication.getName();
		Member member = securityService.findByUserid(username);
		return member;
	}
}
