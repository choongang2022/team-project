package com.oracle.choongangGroup.dongho.auth;

import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import com.oracle.choongangGroup.dongho.auth.CustomAuthenticationProvider;
import com.oracle.choongangGroup.dongho.auth.PrincipalDetailsService;
import com.oracle.choongangGroup.dongho.auth.authutils.CookieUtils;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurtiyConfig {
	private final PrincipalDetailsService principalDetailsService;
	private final SecurityService securityService;
    private final JwtTokenProvider jwtTokenProvider;
    private final HttpServletResponse response;
    private final CookieUtils cookieUtils;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
	
	@Bean
    public SessionRegistry sessionRegistry() {
        SessionRegistry sessionRegistry = new SessionRegistryImpl();
        return sessionRegistry;
    }
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
			.antMatchers("/student/**").hasRole("STUDENT")
			.antMatchers("/manager/**").hasRole("MANAGER")
			.antMatchers("/professor/**").hasRole("PROFESSOR")
			.antMatchers("/admin/**").permitAll()//.hasRole("ADMIN")
            // 권한이 없어도 모두 허용
			.antMatchers("/",
            			 "/login", 
            			 "/anonymous/**"
            			 ).permitAll()
			// 로그인된 사용자만 접근 허용
            .antMatchers(
            			 "/updatePasswordForm",
            			 "/updatePassword"
            			 ).authenticated()
            //.anyRequest().authenticated() //활성화 하면 로그인페이지 두번 요청되는듯하다.
			.and()
			.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, securityService, response, cookieUtils), UsernamePasswordAuthenticationFilter.class)

			//.and()
			.formLogin()
			.loginPage("/").permitAll()
			//.loginProcessingUrl("/login") // JWT custom login 사용하므로 비활성
			.failureUrl("/").permitAll()
			//.defaultSuccessUrl("/main").permitAll()
			//.usernameParameter("securedUsername")
			//.passwordParameter("securedPassword")
			//.successHandler(new CustomSuccessHandler(securityService))
			//.failureHandler(new CustomFailureHandler())
			
			.and()
			.logout()
			.logoutSuccessUrl("/").permitAll()
			.invalidateHttpSession(true)  // 로그아웃 이후 세션 전체 삭제 여부
			.deleteCookies("JSESSIONID", "RefreshToken", "AccessToken", "keepToken")
			.clearAuthentication(true)
			
			.and()
			.sessionManagement()
			.maximumSessions(-1)				 // 최대 허용 가능 세션 수, -1인 경우 무제한 세션
			.maxSessionsPreventsLogin(true) // false : 이전 사용자의 세션 만료, true : 신규 사용자의 인증 실패 
			.expiredUrl("/")
			.sessionRegistry(sessionRegistry());
			
		http.authenticationProvider(new CustomAuthenticationProvider(principalDetailsService , passwordEncoder()));
		
		http.headers().frameOptions().sameOrigin();
			;
		return http.build();
			
	}
	@Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> {
            web.ignoring()
                    .antMatchers(
                            "/images/**",
                            "/js/**",
                            "/css/**",
                            "/favicon.ico",
                            "/ryImgUpload/**",
                            "../default/js/pdf/pdfjs/web/"
                    );
        };
    }
	@Bean
	public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
		return new ServletListenerRegistrationBean<HttpSessionEventPublisher>(new HttpSessionEventPublisher());
	}

}
