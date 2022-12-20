package com.oracle.choongangGroup.dongho.auth;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.oracle.choongangGroup.changhun.JPA.Member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SecurityController {
	// @Secured({"ROLE_STUDENT", "ROLE_MANAGER", "ROLE_PROFESSOR", "ROLE_ADMIN"})
	// @PreAuthorize("isAuthenticated()")
	// @PreAuthorize("hasAnyRole('ROLE_MANAGER', 'ROLE_STUDENT')")
	private final SecurityService securityService;
	private final PasswordEncoder passwordEncoder;
	private final JavaMailSender mailSender;
	private final JwtTokenProvider jwtp;
	private final GetMember gm;

	
	@Value("${spring.mail.username}")
	private String MAIL_USERNAME;
	
	//login성공 후 role 별 main page 연결
	@GetMapping("/student/main")
	public String studentMain() {
			
		return "/student/studentMain";
	}
	@GetMapping("/manager/main")
	public String managerMain() {
		return "/manager/main";
	}
	@GetMapping("/professor/main")
	public String professorMain() {
		return "/professor/main";
	}


	
	// InterCeptor RSA setting 후 loginForm으로 연결
	@GetMapping("/")
    public String loginForm(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) 
    		throws NoSuchAlgorithmException, InvalidKeySpecException {
		log.info("====== loginForm 요청 start ======");
		String targetUrl = "";
		// Request Header cookie 에서 JWT 토큰 추출
        String accessToken  = resolveAccessToken((HttpServletRequest) request);
        String refreshToken = resolveRefreshToken((HttpServletRequest) request);
        String keepToken    = resolveKeepToken((HttpServletRequest) request);
        Authentication authentication =  SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
        if (accessToken != null && refreshToken != null || keepToken != null) {
        	log.info("토큰 존재하므로 메인페이지로 이동");
        	if (roles != null && roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_STUDENT"))) {
    			//response.sendRedirect("/student/main");
    			targetUrl = "/student/main";
    		}
    		else if (roles != null && roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER"))) {
    			//response.sendRedirect("/manager/main");
    			targetUrl = "/manager/main";
    		}
    		else if (roles != null && roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_PROFESSOR"))) {
    			//response.sendRedirect("/professor/main");
    			targetUrl = "/professor/main";
    		}
    		else if (roles != null && roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
    			//response.sendRedirect("/admin/main");
    			targetUrl = "/admin/adminMain";
    		}
		} else {
			log.info("토큰이 없음, 로그인 페이지로 이동");
			targetUrl = "/loginForm";
		}
        return targetUrl;
    }
	
	//로그인 요청
    @PostMapping("/login")
    public void login(@RequestParam(value = "securedUsername") String securedUsername, 
    				  @RequestParam(value = "securedPassword") String securedPassword, 
    				  @RequestParam(value = "keepLogin")       int    keepLogin,
    				  HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
    	// session에서 개인키 받기(loginForm 요청시 session에 저장해둔 개인키)
    	log.info("====login Start====");
    	HttpSession session   = request.getSession();
        PrivateKey privateKey = (PrivateKey)session.getAttribute("__rsaPrivateKey__");
        log.info("login securedUsername : {}", securedUsername);
        String username = null;
        String password = null;
        
        // 복호화 try
        try {
        	username = decryptRSA(privateKey, securedUsername);
        	log.info("복호화 try username : {}", username);
            password = decryptRSA(privateKey, securedPassword);
            log.info("복호화 try username : {}", password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 복호화된 아이디와 비밀번호로 토큰 생성(memberService의 login은 generateToken method를 통해 TokenInfo(토큰dto)를 리턴한다. )
        // 토큰dto에는 타입,refreshToken,accessToken이 들어있음
        TokenInfo tokenInfo = this.securityService.login(username, password, keepLogin);
        String accessToken  = URLEncoder.encode(tokenInfo.getAccessToken(), "utf-8");
        String refreshToken = URLEncoder.encode(tokenInfo.getRefreshToken(), "utf-8");
        
        // DB에 Refresh Token 저장( 추후 Access Token의 유효기간이 끝났을 때 Refresh Token 검증을 위함)
        securityService.saveRefreshToken(refreshToken, username);
        
        // session 에 넣어줄 username setting
        request.setAttribute("userid", username);
        
        // 클라이언트의 쿠키에 넣을 토큰 setting
        ResponseCookie cookieAT = ResponseCookie.from("AccessToken","Bearer" + accessToken)
        		.path("/")
        		.httpOnly(true)
        		.domain("localhost")
//        		.maxAge(7 * 24 * 60 * 60) // 유효시간을 정하지 않으면 session cookie (휘발성. 브라우저종료시 삭제)
        		.build();
		ResponseCookie cookieRT = ResponseCookie.from("RefreshToken","Bearer" + refreshToken)
				.path("/")
        		.httpOnly(true)
        		.domain("localhost")
//        		.maxAge(7 * 24 * 60 * 60) // 유효시간을 정하지 않으면 session cookie (휘발성. 브라우저종료시 삭제)
        		.build();
		response.addHeader("Set-Cookie", cookieAT.toString());
		response.addHeader("Set-Cookie", cookieRT.toString());
		// 자동로그인 토큰 쿠키 setting
		if(keepLogin == 1) {
			String keepToken = URLEncoder.encode(tokenInfo.getKeepToken(), "utf-8");
			ResponseCookie cookieKT = ResponseCookie.from("keepToken","Bearer" + keepToken)
					.path("/")
					.httpOnly(true)
					.domain("localhost")
	        		.maxAge(14 * 24 * 60 * 60) // 유효시간을 정하지 않으면 session cookie (휘발성. 브라우저종료시 삭제)
					.build();
			response.addHeader("Set-Cookie", cookieKT.toString());
		}
    }
	
	
	// InterCeptor RSA setting 후 createMemberForm으로 연결
	@GetMapping("/admin/createMemberForm")
	public String joinForm(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return "/admin/createMemberForm";
	}
	
	@PostMapping("/admin/createMember")
	public void joinProc(Member member, HttpServletResponse response) throws IOException {
		log.info("===joinProc start===");
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		HttpSession session = request.getSession();
        PrivateKey privateKey = (PrivateKey)session.getAttribute("__rsaPrivateKey__");
        log.info("joinProc privateKey : {}", privateKey);
        String encryptedUsername = member.getUserid();
		log.info("joinProc encryptedUsername : {}", encryptedUsername);
		String encryptedPassword = member.getPassword();
		log.info("joinProc encryptedPassword : {}", encryptedPassword);
		String username = null;
		String password = null;
		try {
			username = decryptRSA(privateKey, encryptedUsername);
			log.info("joinProc 복호화 try username : {}", username);
			password = decryptRSA(privateKey, encryptedPassword);
			log.info("joinProc 복호화 try password : {}", password);
			
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		String encodedPassword = passwordEncoder.encode(password);
		member.setUserid(username);
		member.setPassword(encodedPassword);
		securityService.save(member);
		String targetUrl = "/admin/createMemberForm";
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.append(targetUrl);
		out.close();
	}
	
	// createMemberForm 아이디 중복 체크(id 존재 유무) 존재하면 0, 아니면 1
	@PostMapping("/admin/idCheck")
	public void idCheck(@RequestParam("userid") String userid , HttpServletResponse response) throws IOException {
		String result = "0";
		if(securityService.findByUserid(userid) != null) {
			result = "0";
		} else {
			result = "1";
		}
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.append(result);
		out.close();
	}
	
	// createMemberForm 현재비밀번호 체크
	@PostMapping("/admin/pwCheck")
	public void pwCheck(@RequestParam("password") String password ,HttpServletRequest request, HttpServletResponse response) throws IOException {
		String result = "0";
		
		String userid = gm.getMember().getUserid();
		Member member = securityService.findByUserid(userid);
		String dbPassword = member.getPassword();
		
		log.info("pwCheck dbPassword : {}", dbPassword);
		if(member != null && passwordEncoder.matches(password, member.getPassword())) {
			result = "1";
		} else {
			result = "0";
		}
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.append(result);
		out.close();
	}
	
	// RSA setting 후 updatePasswordForm으로 연결

	@GetMapping("/updatePasswordForm")
	public String updatePasswordForm(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return "/admin/updatePasswordForm";
	}
	
	@PostMapping("/updatePassword")
	public void updatePassword(@RequestParam("password") String paramPassword , HttpServletResponse response) throws IOException {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		HttpSession session = request.getSession();
        PrivateKey privateKey = (PrivateKey)session.getAttribute("__rsaPrivateKey__");
        log.info("updatePassword authenticate privateKey : {}", privateKey);
		String password = null;
		try {
			password = decryptRSA(privateKey, paramPassword);
			log.info("updatePassword rsa 복호화 try password : {}", password);
			
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		String userid = gm.getMember().getUserid();
		Member member = securityService.findByUserid(userid);
		String encodedPassword = passwordEncoder.encode(password);
		member.setPassword(encodedPassword);
		securityService.save(member);
		String targetUrl = "/";
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.append(targetUrl);
		out.close();
	}
	
	// 아이디찾기 form 연결
	@GetMapping("/anonymous/findIdForm")
	public String findIdForm() {
		
		return "/admin/findIdForm";
	}
	
	// 아이디찾기 실행 ajax
	@ResponseBody
	@PostMapping("/anonymous/findId")
	public String findId(Member member, HttpServletResponse response, HttpServletRequest request) throws IOException {
		
		String searchId     = member.getName();
		String searchEmail  = member.getEmail();
		Member memberResult = securityService.findByNameAndEmail(searchId , searchEmail);
		String result       = memberResult.getUserid();
//		response.setContentType("text/html");
//		PrintWriter out = response.getWriter();
//		out.append(result);
//		out.close();
		return result;
	}
	
	// 임시 비밀번호 요청 페이지 연결
	@GetMapping("/anonymous/requestResetPwForm")
	public String requestResetPwForm() {
		return "/admin/requestResetPwForm";
	}
	
	// 이메일 발송 요청 전 아이디 이메일 확인 ajax
	@PostMapping("/anonymous/idEmailCheck")
	public void idEmailCheck(Member member , HttpServletResponse response) throws IOException {
		String result = "";
		Optional<Member> memberResult = securityService.findByUseridAndEmail(member.getUserid(), member.getEmail());
		if(memberResult.isPresent()) {
			result = "1";
		} else {
			result = "0";
		}
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
		out.append(result);
		out.close();
	}
	
	// 이메일 전송
	@ResponseBody
	@GetMapping("/anonymous/sendEmail")
	public void sendEmail(HttpServletRequest request, Member member) {
		log.info("sendEmail Start");
		String userid = member.getUserid();
		log.info("sendEmail userid : {}", userid);
		String tomail = member.getEmail();
		log.info("sendEmail tomail : {}", tomail);
		String setfrom = MAIL_USERNAME;
		log.info("sendEmail setfrom : {}", setfrom);
		String title = "임시비밀번호입니다";
		try {
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper messageHelper = new MimeMessageHelper(message, true, "UTF-8");
			messageHelper.setFrom(setfrom);
			messageHelper.setTo(tomail);
			messageHelper.setSubject(title);
			String tempPassword = (int) (Math.random() * 999999) + 1 + "";
			log.info("sendEmail tempPassword : {}", tempPassword);
			messageHelper.setText("임시 비밀번호입니다 : " + tempPassword);
			mailSender.send(message);
			
			Member memberToUpdate = securityService.findByUserid(userid);
			String encodedPassword = passwordEncoder.encode(tempPassword);
			log.info("sendEmail encodedPassword : {}", encodedPassword);
			memberToUpdate.setPassword(encodedPassword);
			securityService.save(memberToUpdate);
			
		} catch (Exception e) {
			log.error("sendEmail exception : " + e.getMessage());
		}
	}
	
	
	// RSA 복호화 method
    public String decryptRSA(PrivateKey privateKey, String securedValue) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] encryptedBytes = hexToByteArray(securedValue);
        cipher.init(2, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decryptedValue = new String(decryptedBytes, "utf-8");
        return decryptedValue;
    }
    
    public static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() % 2 != 0)
            return new byte[0];
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            byte value = (byte)Integer.parseInt(hex.substring(i, i + 2), 16);
            bytes[(int)Math.floor((i / 2))] = value;
        }
        return bytes;
    }
    
    // Request Header (cookie) 에서 keep토큰 정보 추출
    private String resolveKeepToken(HttpServletRequest request) {
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
    private String resolveAccessToken(HttpServletRequest request) {
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
    private String resolveRefreshToken(HttpServletRequest request) {
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
}
