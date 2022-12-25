package com.oracle.choongangGroup.yn.controller;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.JPA.PhoneLike;
import com.oracle.choongangGroup.changhun.address.AddressRepository;
import com.oracle.choongangGroup.changhun.address.AddressService;
import com.oracle.choongangGroup.changhun.address.MemberRepository;
import com.oracle.choongangGroup.changhun.evaluation.EvaService;
import com.oracle.choongangGroup.changhun.evaluation.EvaVo;
import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.hs.managerPage.ManagerPageRepository;
import com.oracle.choongangGroup.hs.managerPage.ManagerPageService;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.dto.NoticeDto;
import com.oracle.choongangGroup.taewoo.repository.NoticeJpaRepository;
import com.oracle.choongangGroup.taewoo.service.NoticeService;
import com.oracle.choongangGroup.yn.repository.LecRepository;
import com.oracle.choongangGroup.yn.service.LecService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
public class ProfessorController {
	
	public final MemberRepository mrr;
	private final ManagerPageRepository mr;
	private final AddressService addressService;
	private final ManagerPageService ms;
	private final LecService ls;
	private final LecRepository lr;
	
	private final GetMember gm;
	public final AddressRepository ar;
	
	private final NoticeService noticeService;
	private final NoticeJpaRepository noticeJpaRepository;
	private final GetMember getMember;
	private final EvaService es;
	
	
	@GetMapping(value = "professor/professorMain")
	@PreAuthorize("isAuthenticated()")
	public String professorMain(Model model, @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		
		System.out.println("LecController professorMain 시작 ==============");
		String mainCheck = "1";
		String name = gm.getMember().getName();
		System.out.println(name);
		
		///////// 접속교수 이름 받아서 넘기기////////////
		List<Lecture> lectureList = lr.findByProfAndStatusOrderByIdAsc(name, "0");
		
		List<Map<String, Object>> mapList = new ArrayList<Map<String,Object>>();
		for(Lecture lecList : lectureList) {
			Map<String, Object> map = new HashMap<String, Object>();
			map.put("lecture", lecList);
			List<ApplicationLec> alList = ls.findByLecture_IdAndGubun(lecList.getId(), 1L);
			map.put("memberCnt", alList.size());
			mapList.add(map);
		}
		
		Page<Notice> noticeList = noticeJpaRepository.findByNoticeTypeOrNoticeType(PageRequest.of(page, 5, Sort.by(Sort.Direction.DESC,"noticeNum")), "ROLE_PROFESSOR", "allContent");
		int noticeTotal = noticeList.getTotalPages();
		model.addAttribute("member" , getMember.getMember());
		model.addAttribute("page",page);
		model.addAttribute("noticeTotal", noticeTotal);
		model.addAttribute("noticeList", noticeList.getContent());
		
		System.out.println(lectureList.size());
		model.addAttribute("mainCheck", mainCheck);
		model.addAttribute("lecList", mapList);
		model.addAttribute("lecCnt", lectureList.size());
		
		model.addAttribute("member", gm.getMember());
		return "professor/main";
	}
	
// ------------------ 마이페이지 --------------------------
		@RequestMapping("professor/mypage")
		public String form(Model model) {
			log.info("mypage Start...");
			String userid = gm.getMember().getUserid();
			Member member = ms.findByUserid(userid);
			
			try {
				String strDate = member.getBirth();
				SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMdd");
				Date birth = dateFormat.parse(strDate);
				String birthDate = new SimpleDateFormat("yyyy-MM-dd").format(birth);
				member.setBirth(birthDate);
			} catch (Exception e) {
				log.info("mypage Exception->{}", e.getMessage());
			}
			
			model.addAttribute("mypage", member);
			model.addAttribute("member", gm.getMember());
			model.addAttribute("mem", gm.getMember());
			return "professor/professorMypage";
		}
		
		@RequestMapping("professor/mypageSave")
		public String save(@ModelAttribute("member") Member member, MultipartFile file1, HttpServletRequest request) throws IOException, Exception {
			log.info("mypage save...");
			String userid = gm.getMember().getUserid();
			Member findMember = mr.findByUserid(userid);
			if(!file1.isEmpty()) {
				// 파일 저장
				String filePath = request.getSession().getServletContext().getRealPath("/fileUpload/hs/image/");
				String serverFileName = uploadFile(file1.getOriginalFilename(), file1.getBytes(), filePath);
				
				findMember.setImage(serverFileName);
			}
			findMember.setAddress(member.getAddress());
			findMember.setEmail(member.getEmail());
			findMember.setPhone(member.getPhone());
			findMember.setSubphone(member.getSubphone());
			mr.save(findMember);
			return "redirect:/professor/mypage";
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
		
		/************************/
		/******* 주소록페이지 *******/
		/***********************/
		@RequestMapping(value = "professor/addressForm")
		public String addressForm(Model model,
				 				  @RequestParam(required = false, defaultValue = "0", value="page") int page) {
			
			Page<Member> addressList = mr.findAll(PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"name")));
			
			int totalPage = addressList.getTotalPages();
			
			model.addAttribute("member", gm.getMember());
			model.addAttribute("page", page);
			model.addAttribute("totalPage", totalPage);
			model.addAttribute("addressList",addressList.getContent());
			
			return "professor/professorAddressForm";
		}
		
		@RequestMapping(value = "professor/myLikeAddress")
		public String likeAddress(HttpServletRequest request, Model model,
								  @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		
			String userid = gm.getMember().getUserid();
			
			Page<PhoneLike> like = ar.findByMyUserid(userid, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"member.name")));
			
			int totalPage = like.getTotalPages();
			
			System.out.println("totalpage -> " + totalPage);
			
			model.addAttribute("member", gm.getMember());
			model.addAttribute("page", page);
			model.addAttribute("totalPage", totalPage);
			model.addAttribute("likeList",like.getContent());
			
			return "professor/professorAddressLike";
		}
		
		@RequestMapping(value = "professor/searchAddress")
		public String searchAddress(Model model,HttpServletRequest request,
									@RequestParam(value = "search") String name,
						  			@RequestParam(required = false, defaultValue = "0", value="page") int page) {
			
		Page<Member> addressList = null;
		
		Member member = gm.getMember();
		
		if(name == null || name.equals("")) {
			addressList = mr.findAll(PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"name")));
		} else {
			addressList = mrr.findByNameContaining(name, PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC,"name")));
		}
		
		int totalPage = addressList.getTotalPages();
		
		model.addAttribute("member", member);
		model.addAttribute("page", page);
		model.addAttribute("totalPage", totalPage);
		model.addAttribute("addressList",addressList.getContent());
		
		return "professor/professorAddressForm";
		}
		
		@RequestMapping("professor/phoneLikeSave")
		@ResponseBody
		public String phoneLikeSave(@RequestParam(value = "userid") String userid) {
			String msg = null;
			
			log.info("userid 값은? -> {}",userid);
			Member member = gm.getMember();
			
			try {
				addressService.phoneLikeSave(userid,member.getUserid());			
			} catch (Exception e) {
				msg = "이미 등록된 주소록입니다!";
			}
			return msg;
		}
		
		@RequestMapping("professor/phoneLikeDelete")
		@ResponseBody
		public String phoneLikeDelete(@RequestParam(value = "myUserid") String myuserid,
									  @RequestParam(value = "userid") String userid) {
			addressService.phoneLikeDelete(myuserid,userid);
		return null;
		}
		
		/************************/
		/******** 공지사항 ********/
		/***********************/
		//공지사항 List
		@GetMapping(value = "professor/notice/noticeList")
		@PreAuthorize("isAuthenticated()")
		public String listPage(Model model,
							   @RequestParam(required = false, defaultValue = "0", value="page") int page) {
			
			Page<Notice> noticeList = noticeJpaRepository.findByNoticeTypeOrNoticeType(PageRequest.of(page, 10, Sort.by(Sort.Direction.DESC,"noticeNum")), "ROLE_PROFESSOR", "allContent");
			int noticeTotal = noticeList.getTotalPages();
			Member member = getMember.getMember();
			model.addAttribute("member" , member);
			model.addAttribute("page",page);
			model.addAttribute("noticeTotal", noticeTotal);
			model.addAttribute("noticeList", noticeList.getContent());
			
			return "professor/notice/noticeList";		
		}
		
		// 검색 기능
		@RequestMapping(value = "professor/notice/search")
		@PreAuthorize("isAuthenticated()")
		public String SearchNotice(Model model, String keyword) {
			List<Notice> searchNotice = noticeService.searchNotice(keyword);
			String msg = "";
			if(searchNotice == null) {
				msg += "다시 입력해주세요";
			}
			model.addAttribute("msg",msg);
			model.addAttribute("noticeList",searchNotice);
			model.addAttribute("member", gm.getMember());
			return "professor/notice/noticeList";
		}
		
		// 상세화면
		@RequestMapping(value = "professor/noticeDetail")
		@PreAuthorize("isAuthenticated()")
		public String detail(@RequestParam Long noticeNum, Model model, HttpServletRequest request, HttpServletResponse response, NoticeDto noticeDto) {
			log.info("Detail start...");
			System.out.println("noticeNum -> " + noticeNum);		
			Member member = getMember.getMember();
			Notice notice = noticeService.findById(noticeNum);
			model.addAttribute("member" , member);
			model.addAttribute("notice", notice );
			noticeService.updateHit(noticeNum,request,response);
			return "professor/notice/noticeDetail";
		}
		
		/************************/
		/******** 강의평가 ********/
		/***********************/
		@RequestMapping("professor/EvaManagementForm")
		public String EvaManagementForm(Model model,
										@RequestParam(value = "pname") String pname) {
			pname = gm.getMember().getName();
			
			log.info("EvaManagementForm pname --> {}",pname);
			
			model.addAttribute("member", getMember.getMember());
			model.addAttribute("evaList", es.evaList(pname));
			model.addAttribute("reviewList", es.reviewList(pname));
			model.addAttribute("total", es.total(pname));
			
			return "professor/EvaManagementForm";
		}
		
		@ResponseBody
		@RequestMapping("professor/findProf")
		public List<String> findProf(){
			
			List<String> profList = es.profList();
			
			return profList;
			
		}
		
	// 캘린더이동 ---> 작업중 : 일단 연결만
//	@GetMapping(value = "professor/calenderForm") public String lecList(Model model) { //
//	String name = gm.getMember().getName();
//	String userid = gm.getMember().getUserid();
//	System.out.println(name);
//	return "/professor/calenderForm"; }

	

}
