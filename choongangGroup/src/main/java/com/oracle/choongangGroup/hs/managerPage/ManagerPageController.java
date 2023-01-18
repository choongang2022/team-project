package com.oracle.choongangGroup.hs.managerPage;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.sh.domain.ApplyTime;
import com.oracle.choongangGroup.sh.service.ApplyService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/manager")
public class ManagerPageController {
	
	private final ManagerPageService ms;
	private final ManagerPageRepository mr;
	private final ManagerPageRepositoryImpl mi;
	private final GetMember gm;
	private final ApplyService as; //신효 
	
	
	// ------------------ 마이페이지 --------------------------
	@RequestMapping("/mypage")
	public String form(Model model) {
		log.info("mypage Start...");
		Member member = gm.getMember();
		String userid = gm.getMember().getUserid();
		Member mypage = ms.findByUserid(userid);
		
		try {
			String strDate = mypage.getBirth();
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMdd");
			Date birth = dateFormat.parse(strDate);
			String birthDate = new SimpleDateFormat("yyyy-MM-dd").format(birth);
			mypage.setBirth(birthDate);
		} catch (Exception e) {
			log.info("mypage Exception->{}", e.getMessage());
		}
		
		model.addAttribute("member", member);
		model.addAttribute("mypage", mypage);
		return "/manager/mypage";
	}
	
	@RequestMapping("/mypageSave")
	public String save(@ModelAttribute("member") Member member, MultipartFile file1, HttpServletRequest request) throws IOException, Exception {
		log.info("mypage save...");
		String userid = gm.getMember().getUserid();
		Member findMember = mr.findByUserid(userid);
		if(!file1.isEmpty()) {
			// 파일 저장
			String filePath = request.getSession().getServletContext().getRealPath("/upload/hj/");
			log.info("file POST Start...");
			log.info("originalName: {}", file1.getOriginalFilename());
			log.info("size: {}", file1.getSize());
			log.info("contentType: {}", file1.getContentType());
			log.info("filePath: {}", filePath);
			String serverFileName = uploadFile(file1.getOriginalFilename(), file1.getBytes(), filePath);
			log.info("serverFileName: {}", serverFileName);
			
			findMember.setAddress(member.getAddress());
			findMember.setEmail(member.getEmail());
			findMember.setPhone(member.getPhone());
			findMember.setSubphone(member.getSubphone());
			findMember.setImage(serverFileName);
			log.info(findMember.getImage());
			mr.save(findMember);
			return "redirect:/manager/mypage";
		} else {
			findMember.setAddress(member.getAddress());
			findMember.setEmail(member.getEmail());
			findMember.setPhone(member.getPhone());
			findMember.setSubphone(member.getSubphone());
			mr.save(findMember);
		}
		return "redirect:/manager/mypage";
	}
	
	// 이미지 업로드 메서드
	private String uploadFile(String originalName, byte[] fileData, String uploadPath) throws Exception {
		// universally unique identifier (UUID).
		UUID uid = UUID.randomUUID();
		// requestPath = requestPath + "/resources/image";
		log.info("uploadPath->{}",uploadPath);
		// Directory 생성
		File fileDirectory = new File(uploadPath);
		if (!fileDirectory.exists()) {
			fileDirectory.mkdir(); // mkdir 신규 폴더 생성
			log.info("업로드용 폴더 생성 : {}", uploadPath);
		}
		
		String savedName = uid.toString() + "_" + originalName;
		log.info("savedName: {}", savedName);
		File target = new File(uploadPath, savedName);
		// File target = new File(requestPath, savedName);
		// File Upload -> uplaodPath / UUID+_+originalName
		FileCopyUtils.copy(fileData, target); // org.springframework.util.FileCopyUtils
		
		return savedName;
	}
	
	
	// ------------------ 학생 수정 --------------------------
	@RequestMapping("/studentManage")
	public String stuList(@RequestParam(required = false, defaultValue = "0", value="page") int page, Model model) {
		Member member = gm.getMember();
		log.info("stuList Start...");
		String memRole = "ROLE_STUDENT";
		Page<Member> studentList = mr.findByMemRole(memRole, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"admission", "name")));
		int pageTotal = studentList.getTotalPages();
		Long stuTotal = studentList.getTotalElements();
		
		model.addAttribute("member", member);
		model.addAttribute("studentList", studentList.getContent());
		model.addAttribute("page",page);
		model.addAttribute("pageTotal", pageTotal);
		model.addAttribute("stuTotal", stuTotal);
		return "/manager/studentManage";
	}
	
	@ResponseBody
	@RequestMapping("studSearch")
	public List<Member> searchStud(Member member, Model model) {
		log.info("searchStud");
		String memRole = "ROLE_STUDENT";
		List<Member> searchList = mi.searchStud(member, memRole);
		model.addAttribute("studCnt", searchList.size());
		
		return searchList;
	}
	
	@ResponseBody
	@RequestMapping("studDetail")
	public Member studDetail(@RequestParam(value = "userid") String userid, Model model) {
		log.info("studDetail");
		String memRole = "ROLE_STUDENT";
		Member student = mr.findByMemRoleAndUserid(memRole, userid);
		
		try {
			String strDate = student.getBirth();
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMdd");
			Date birth = dateFormat.parse(strDate);
			String birthDate = new SimpleDateFormat("yyyy-MM-dd").format(birth);
			student.setBirth(birthDate);
		} catch (Exception e) {
			log.info("mypage Exception->{}", e.getMessage());
		}
		model.addAttribute("student", student);
		return student;
	}
	
	@RequestMapping("studUpdate")
	public String studUpdate(@ModelAttribute("member") Member member) {
		String memRole = "ROLE_STUDENT";
		String userid = member.getUserid();
		Member findMember = mr.findByMemRoleAndUserid(memRole, userid);
		log.info("studUpdate start...");
		
		findMember.setGender(member.getGender());
		findMember.setMajor(member.getMajor());
		findMember.setNation(member.getNation());
		findMember.setStudStatus(member.getStudStatus());
		
		mr.save(findMember);
		return "redirect:/manager/studentManage";
	}
	
	// ------------------ 교수 수정 --------------------------
	@RequestMapping("/professorManage")
	public String proList(@RequestParam(required = false, defaultValue = "0", value="page") int page, Model model) {
		log.info("proList Start...");
		Member member = gm.getMember();
		String memRole = "ROLE_PROFESSOR";
		Page<Member> professorList = mr.findByMemRole(memRole, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"hiredate", "name")));
		int pageTotal = professorList.getTotalPages();
		Long proTotal = professorList.getTotalElements();
		
		model.addAttribute("member", member);
		model.addAttribute("professorList", professorList.getContent());
		model.addAttribute("page",page);
		model.addAttribute("pageTotal", pageTotal);
		model.addAttribute("proTotal", proTotal);
		return "/manager/professorManage";
	}
	
	@ResponseBody
	@RequestMapping("proSearch")
	public List<Member> proSearch(Member member, Model model) {
		log.info("proSearch");
		String memRole = "ROLE_PROFESSOR";
		List<Member> searchProList = mi.searchPro(member, memRole);
		model.addAttribute("proCnt", searchProList.size());
		
		return searchProList;
	}
	
	@ResponseBody
	@RequestMapping("proDetail")
	public Member proDetail(@RequestParam(value = "userid") String userid, Model model) {
		log.info("proDetail");
		String memRole = "ROLE_PROFESSOR";
		Member professor = mr.findByMemRoleAndUserid(memRole, userid);
		
		try {
			String strDate = professor.getBirth();
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMdd");
			Date birth = dateFormat.parse(strDate);
			String birthDate = new SimpleDateFormat("yyyy-MM-dd").format(birth);
			professor.setBirth(birthDate);
		} catch (Exception e) {
			log.info("mypage Exception->{}", e.getMessage());
		}
		
		log.info("교수 부서->{}",professor.getDept().getDname());
		model.addAttribute("professor", professor);
		return professor;
	}
	
	@RequestMapping("proUpdate")
	public String proUpdate(@ModelAttribute("member") Member member) {
		String memRole = "ROLE_PROFESSOR";
		String userid = member.getUserid();
		Member findMember = mr.findByMemRoleAndUserid(memRole, userid);
		log.info("proUpdate start...");
		
		findMember.setGender(member.getGender());
		findMember.setMajor(member.getMajor());
		findMember.setNation(member.getNation());
		findMember.setPosition(member.getPosition());
		findMember.setLab(member.getLab());
		
		mr.save(findMember);
		return "redirect:/manager/professorManage";
	}
	
	//----------------- 신효 : 수강신청/장바구니 기간 등록-------------------------------
	//장바구니, 수강신청 기간 등록 폼
	@GetMapping(value = "registerTimeForm")
	public String registerTimeForm(Model model){
		String year = getYear();
		String semester = getSemester();
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		return "manager/registerTimeForm";
	}

	//기간 등록
	@GetMapping(value = "registerTime")
	public String registerTime(ApplyTime applyTime) { //@ModelAttribute 생략
		
		int result = as.register(applyTime);
	
		return "manager/registerTime";
	}
	
	//현재 년도 구하기
	public String getYear() {
		LocalDate now = LocalDate.now();
		String year = String.valueOf(now.getYear());
		return year;
	}
	
	//현재 학기 구하기
	public String getSemester() {
		LocalDate now = LocalDate.now();
		int month = now.getMonthValue();
		String semester = "";
		if(month>=1 && month<=6) {
			semester = "1";					
		}else {
			semester = "2";			
		}
		
		return semester;
	}
}
