package com.oracle.choongangGroup.hj.controller;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.hj.model.GradeVo;
import com.oracle.choongangGroup.hj.model.MemberVo;
import com.oracle.choongangGroup.hj.service.MemberService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/student/")
public class MemberController {

	private final MemberService ms;
	private final GetMember gm;

	// 아이디 받아와서 학적 조회
	@RequestMapping(value = "listEmp")
	public String MemberList( Model model ) {
		System.out.println("MemberController MemberList start. . .  . . ");
	
		String userid = gm.getMember().getUserid();
				

		
		MemberVo member = ms.list(userid);
		model.addAttribute("member", member);
		model.addAttribute("userid", userid);

		return "student/detailList";
	}

	//학적수정화면
	@GetMapping(value = "updateFormMember")
	public String updateFormMember( Model model) {
		System.out.println(" MemberController updateFormMember start . . . ");
		String userid = gm.getMember().getUserid();
		MemberVo member = ms.list(userid);
		model.addAttribute("member", member);
		model.addAttribute("userid", userid);

		return "student/updateFormMember";

	}

	//  학적 수정
	//파일업로드
	@PostMapping(value = "updateMember")
	public String updateEmp(MemberVo member, Model model   , HttpServletRequest request, MultipartFile file1) throws IOException, Exception {
		log.info("MemberController updateEmp start. . . ");
        System.out.println("member---->"+member);
        
        
      //파일업로드
        String uploadPath = request.getSession().getServletContext().getRealPath("/upload/hj/");
	      log.info("uploadForm POST Start...");
	      log.info("originalName: {}", file1.getOriginalFilename());
	      log.info("size: {}", file1.getSize());
	      log.info("contentType: {}", file1.getContentType());
	      log.info("uploadPath: {}", uploadPath);
	      //밑에서 리턴시킨 파일을 받음 
	      String savedName = uploadFile(file1.getOriginalFilename(), file1.getBytes(), uploadPath);
	      log.info("savedName: {}", savedName);
           member.setImage(savedName);
        
           //수정
		int updateCount = ms.updateMember(member);

		model.addAttribute("uptcnt", updateCount);
		return "redirect:listEmp ";	
		

	}
	 
	 // 이미지 업로드 메서드
	   private String uploadFile(String originalName, byte[] fileData, String uploadPath) throws Exception {
	      // universally unique identifier (UUID).( 국제적으로 유일한 구별자 )
	      UUID uid = UUID.randomUUID(); //랜덤한 아이디를 뽑고 싶을때 uuid를 뽑음 ->똑같은 사진올릴때 파일명이 중첩되지 않음
	      // requestPath = requestPath + "/resources/image"; 
	      log.info("uploadPath->{}",uploadPath);
	      // Directory 생성
	      File fileDirectory = new File(uploadPath); //파일 업로드가져온거를 만듬
	      if (!fileDirectory.exists()) { //존재하지 않는다면
	         fileDirectory.mkdir(); // mkdir 신규 폴더 생성 //mkdirs(make)라는 메소드 제공 --> 파일을 알아서 만듬(-> uploadPath)
	         log.info("업로드용 폴더 생성 : {}", uploadPath);
	      }
	      
	      String savedName = uid.toString() + "_" + originalName; //두번올려도 계속 파일은 올라감
	      log.info("savedName: {}", savedName);
	      File target = new File(uploadPath, savedName);  //폴더명하고 파일명을 합쳐서 target만들어줌
	      // File target = new File(requestPath, savedName);
	      // File Upload -> uplaodPath / UUID+_+originalName
	      FileCopyUtils.copy(fileData, target); // org.springframework.util.FileCopyUtils
	      							//파일의크기를 타겟에다가 복사해서 알아서 업로드해줌
			
	      return savedName;  //올려준 파일이름을 리턴시킴 
	   }

	

	// 성적조회페이지
	@GetMapping(value = "gradeList")
	public String gradeListForm( Model model, HttpServletRequest request) {
		System.out.println(" MemberController gradeListForm start . . . ");
       //아이디 받아오기
		String userid = gm.getMember().getUserid();
		// 이름 가져오기위해서 해줌
		MemberVo memberinfo = ms.infoList(userid);

		// 셀렉트바  학년 년도
		List<GradeVo> ysList = ms.findys(userid);
	
		//총 학점 평균 조회
		GradeVo grade = ms.sutotal(userid);
		grade.setStotal(grade.getStotal());   //신청학점토탈 
		grade.setUtotal(grade.getUtotal());		//신청한 성적토탈 
		grade.setMajorutotal(grade.getMajorutotal());   //신청한 전공학점토탈
		grade.setSubutotal(grade.getSubutotal());		//신청한 교양학점토탈 
		grade.setAvg(grade.getAvg());   //총성적평균
		grade.setPercentile(grade.getPercentile()); //백분위 
		grade.setSco_attendance(grade.getSco_attendance()); //출석상태
		grade.setPtotal(grade.getPtotal());
		
	   
		
	
		
		model.addAttribute("member", memberinfo);
		model.addAttribute("ysList"  , ysList);
		model.addAttribute("grade", grade);
        
	

		return "student/gradeListForm";
	}

	//년도학기별로 신청한 과목 성적 조회
	//ajax 사용해서 넘어옴 
	@ResponseBody
	@GetMapping(value = "gradeDetailList")
	public List<GradeVo> gradeDetailList(String userid ,String ys) {

	
	System.out.println(" MemberController gradeDetailList start . . . ");
	System.out.println("넘어온 userid *************** >"+userid);
	System.out.println( "넘어온 lec_year *********** >  "+ys );
	
	//년도 학기 따로 조회하기위해 짤라주기  --> 2022,2 
	String lec_year = ys.substring(0,4);    //2022
	String lec_semester= ys.substring(5,6);    //2
	

	System.out.println(" lec_year짜름 ---------->"+lec_year);
	System.out.println(" lec_semester짜름 ------->"+lec_semester);
	

	//성적조회할대 짤라준 년도 학기 넣기 
	List<GradeVo> gradeList = ms.listgrade(userid ,lec_year, lec_semester);
	System.out.println("gradeList :" + gradeList.get(0).toString());
	

	
	//아작스의 성공시(data)에 gradeList 들어감 
	return gradeList;


	}

	
	


}
