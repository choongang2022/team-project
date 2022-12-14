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
	
	//login?????? ??? role ??? main page ??????
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


	
	// InterCeptor RSA setting ??? loginForm?????? ??????
	@GetMapping("/")
    public String loginForm(HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) 
    		throws NoSuchAlgorithmException, InvalidKeySpecException {
		log.info("====== loginForm ?????? start ======");
		String targetUrl = "";
		// Request Header cookie ?????? JWT ?????? ??????
        String accessToken  = resolveAccessToken((HttpServletRequest) request);
        String refreshToken = resolveRefreshToken((HttpServletRequest) request);
        String keepToken    = resolveKeepToken((HttpServletRequest) request);
        Authentication authentication =  SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
        if (accessToken != null && refreshToken != null || keepToken != null) {
        	log.info("?????? ??????????????? ?????????????????? ??????");
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
			log.info("????????? ??????, ????????? ???????????? ??????");
			targetUrl = "/loginForm";
		}
        return targetUrl;
    }
	
	//????????? ??????
    @PostMapping("/login")
    public void login(@RequestParam(value = "securedUsername") String securedUsername, 
    				  @RequestParam(value = "securedPassword") String securedPassword, 
    				  @RequestParam(value = "keepLogin")       int    keepLogin,
    				  HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
    	// session?????? ????????? ??????(loginForm ????????? session??? ???????????? ?????????)
    	log.info("====login Start====");
    	HttpSession session   = request.getSession();
        PrivateKey privateKey = (PrivateKey)session.getAttribute("__rsaPrivateKey__");
        log.info("login securedUsername : {}", securedUsername);
        String username = null;
        String password = null;
        
        // ????????? try
        try {
        	username = decryptRSA(privateKey, securedUsername);
        	log.info("????????? try username : {}", username);
            password = decryptRSA(privateKey, securedPassword);
            log.info("????????? try username : {}", password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // ???????????? ???????????? ??????????????? ?????? ??????(memberService??? login??? generateToken method??? ?????? TokenInfo(??????dto)??? ????????????. )
        // ??????dto?????? ??????,refreshToken,accessToken??? ????????????
        TokenInfo tokenInfo = this.securityService.login(username, password, keepLogin);
        String accessToken  = URLEncoder.encode(tokenInfo.getAccessToken(), "utf-8");
        String refreshToken = URLEncoder.encode(tokenInfo.getRefreshToken(), "utf-8");
        
        // DB??? Refresh Token ??????( ?????? Access Token??? ??????????????? ????????? ??? Refresh Token ????????? ??????)
        securityService.saveRefreshToken(refreshToken, username);
        
        // session ??? ????????? username setting
        request.setAttribute("userid", username);
        
        // ?????????????????? ????????? ?????? ?????? setting
        ResponseCookie cookieAT = ResponseCookie.from("AccessToken","Bearer" + accessToken)
        		.path("/")
        		.httpOnly(true)
        		.domain("localhost")
//        		.maxAge(7 * 24 * 60 * 60) // ??????????????? ????????? ????????? session cookie (?????????. ????????????????????? ??????)
        		.build();
		ResponseCookie cookieRT = ResponseCookie.from("RefreshToken","Bearer" + refreshToken)
				.path("/")
        		.httpOnly(true)
        		.domain("localhost")
//        		.maxAge(7 * 24 * 60 * 60) // ??????????????? ????????? ????????? session cookie (?????????. ????????????????????? ??????)
        		.build();
		response.addHeader("Set-Cookie", cookieAT.toString());
		response.addHeader("Set-Cookie", cookieRT.toString());
		// ??????????????? ?????? ?????? setting
		if(keepLogin == 1) {
			String keepToken = URLEncoder.encode(tokenInfo.getKeepToken(), "utf-8");
			ResponseCookie cookieKT = ResponseCookie.from("keepToken","Bearer" + keepToken)
					.path("/")
					.httpOnly(true)
					.domain("localhost")
	        		.maxAge(14 * 24 * 60 * 60) // ??????????????? ????????? ????????? session cookie (?????????. ????????????????????? ??????)
					.build();
			response.addHeader("Set-Cookie", cookieKT.toString());
		}
    }
	
	
	// InterCeptor RSA setting ??? createMemberForm?????? ??????
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
			log.info("joinProc ????????? try username : {}", username);
			password = decryptRSA(privateKey, encryptedPassword);
			log.info("joinProc ????????? try password : {}", password);
			
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
	
	// createMemberForm ????????? ?????? ??????(id ?????? ??????) ???????????? 0, ????????? 1
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
	
	// createMemberForm ?????????????????? ??????
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
	
	// RSA setting ??? updatePasswordForm?????? ??????

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
			log.info("updatePassword rsa ????????? try password : {}", password);
			
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
	
	// ??????????????? form ??????
	@GetMapping("/anonymous/findIdForm")
	public String findIdForm() {
		
		return "/admin/findIdForm";
	}
	
	// ??????????????? ?????? ajax
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
	
	// ?????? ???????????? ?????? ????????? ??????
	@GetMapping("/anonymous/requestResetPwForm")
	public String requestResetPwForm() {
		return "/admin/requestResetPwForm";
	}
	
	// ????????? ?????? ?????? ??? ????????? ????????? ?????? ajax
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
	
	// ????????? ??????
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
		String title = "???????????????????????????";
		try {
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper messageHelper = new MimeMessageHelper(message, true, "UTF-8");
			messageHelper.setFrom(setfrom);
			messageHelper.setTo(tomail);
			messageHelper.setSubject(title);
			String tempPassword = (int) (Math.random() * 999999) + 1 + "";
			log.info("sendEmail tempPassword : {}", tempPassword);
			messageHelper.setText("?????? ????????????????????? : " + tempPassword);
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
	
	
	// RSA ????????? method
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
    
    // Request Header (cookie) ?????? keep?????? ?????? ??????
    private String resolveKeepToken(HttpServletRequest request) {
    	Cookie[] list = request.getCookies();
        String bearerToken = "";
        if (list != null) {
        	for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("keepToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// ?????? value?????? bearer ?????? ????????? token??? ??????
    		            return bearerToken.substring(6);
    		        }
    			}
    		}
		}
		return null;
	}
    
    // Request Header (cookie) ?????? access?????? ?????? ??????
    private String resolveAccessToken(HttpServletRequest request) {
        Cookie[] list = request.getCookies();
        String bearerToken = "";
        if (list != null) {
        	for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("AccessToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// ?????? value?????? bearer ?????? ????????? token??? ??????
    		            return bearerToken.substring(6);
    		        }
    			}
    		}
		}
		return null;
    }
    
    // Request Header (cookie) ?????? refresh?????? ?????? ??????
    private String resolveRefreshToken(HttpServletRequest request) {
    	Cookie[] list = request.getCookies();
    	String bearerToken = "";
    	if (list != null) {
    		for (Cookie cookie : list) {
    			if (cookie != null && cookie.getName().equals("RefreshToken")) {
    				bearerToken = cookie.getValue();
    				if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
    					// ?????? value?????? bearer ?????? ????????? token??? ??????
    					return bearerToken.substring(6);
    				}
    			}
    		}
    	}
    	return null;
    }
}
