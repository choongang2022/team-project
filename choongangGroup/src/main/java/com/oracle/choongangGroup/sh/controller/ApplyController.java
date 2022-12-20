package com.oracle.choongangGroup.sh.controller;




import java.io.File;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.dongho.professor.report.DhProfessorReportService;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.ApplyTime;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;
import com.oracle.choongangGroup.sh.service.ApplyService;


import lombok.RequiredArgsConstructor;
import lombok.val;




@RequestMapping("/student/")
@Controller
@RequiredArgsConstructor
public class ApplyController {

	private final ApplyService as;
	private final GetMember gm;

	
	
	
	//기간안내  & 수강신청,장바구니 선택 페이지 
	@GetMapping(value = "applyIndex")
	public String applyIndex(Model model) {
		
		String userid = gm.getMember().getUserid();
		String year = getYear();
		String semester = getSemester();
		
		
		String now = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
		
		
		//장바구니 기간 불러오기
		String select = "like";
		ApplyTime likeTime = as.findTime(year, semester, select);
		//수강신청 기간 불러오기
		select = "apply";
		ApplyTime applyTime = as.findTime(year, semester, select);
		
		int nowInt = Integer.parseInt(now);
		int likeStartInt = Integer.parseInt(likeTime.getStart());
		int likeEndInt = Integer.parseInt(likeTime.getEnd());
		int applyStartInt = Integer.parseInt(applyTime.getStart());
		int applyEndInt = Integer.parseInt(applyTime.getEnd());
		
		String likeResult="";
		String applyResult="";
		if(nowInt>=likeStartInt && nowInt<=likeEndInt) {
			likeResult = "ok";
		}else {
			likeResult = "likeWrong";
		}
		
		if(nowInt>=applyStartInt && nowInt<=applyEndInt) {
			applyResult = "ok";
		}else {
			applyResult = "applyWrong";
		}
		
		Member member = gm.getMember();
		model.addAttribute("member", member);
		model.addAttribute("likeTime", likeTime);
		model.addAttribute("applyTime", applyTime);
		model.addAttribute("userid", userid);
		model.addAttribute("likeResult", likeResult);
		model.addAttribute("applyResult", applyResult);
		
		return "student/applyIndex"; 
	}
	
	//장바구니 메인 [장바구니안내문, 신청, 시간표]
	@GetMapping(value = "likeMain")
	///////////장바구니 기간 넘겨주기///////////
	public String likeMain(String userid, Model model) {
		model.addAttribute("userid", userid);
		
		Member member = gm.getMember();
		model.addAttribute("member", member);
		return "student/likeMain";
	}
	
	//장바구니 신청 페이지
	@GetMapping(value = "likeForm")
	public String likeForm(String userid, String lecName, Model model, @PageableDefault(size = 10, sort = "id", direction = Sort.Direction.DESC) Pageable pageable) {			
		Member member = gm.getMember();
		model.addAttribute("member", member);
		
		String year = getYear();
		String semester = getSemester();
		if(lecName.isEmpty()) {
			lecName = "empty";
		}
		
	
		//페이징
		Page<Lecture> lectureList = as.lectureList(year,semester,pageable);
		Page<Lecture> lectureSearch = as.findByName(year,semester,lecName,pageable); //강의명으로 검색한 목록 
		if(!lecName.equals("empty")) {
			int pageNum = lectureSearch.getPageable().getPageNumber(); //현재페이지
			int totalPage = lectureSearch.getTotalPages();//총페이지수
			int pageBlock = 5; //블럭의 수
			int startBlockPage = ((pageNum)/pageBlock)*pageBlock+1; 		
			int endBlockPage = startBlockPage+pageBlock-1;
			endBlockPage= totalPage<endBlockPage? totalPage:endBlockPage;
			model.addAttribute("startBlockPage", startBlockPage);
			model.addAttribute("endBlockPage", endBlockPage);
			model.addAttribute("lectureList", lectureSearch);
		}else {
			int pageNum = lectureList.getPageable().getPageNumber(); //현재페이지
			System.out.println("likeForm pageNum ------------------------->"+pageNum);
			int totalPage = lectureList.getTotalPages();//총페이지수
			int pageBlock = 5; //블럭의 수
			int startBlockPage = ((pageNum)/pageBlock)*pageBlock+1; 		
			int endBlockPage = startBlockPage+pageBlock-1;
			endBlockPage= totalPage<endBlockPage? totalPage:endBlockPage;
			model.addAttribute("startBlockPage", startBlockPage);
			model.addAttribute("endBlockPage", endBlockPage);
			model.addAttribute("lectureList", lectureList);		
		}//페이징 끝
		
		//시간표
		List<ApplicationLec> likeList = as.likeList(userid, year, semester);
		
		//요일 리스트
		List<String> day = new ArrayList<String>();
		day.add("월");day.add("화");day.add("수");day.add("목");day.add("금");
		
		//총 신청학점
		int totalUnit =  totalUnit(likeList);
		
		model.addAttribute("list", likeList);
		model.addAttribute("day", day);
		model.addAttribute("userid", userid);	
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		model.addAttribute("unit", totalUnit);
		
		return "student/likeForm";
	}
	
	//장바구니 신청
	@ResponseBody
	@GetMapping(value = "like")
	public int like(Long lecId, String userid,  Model model) {
		
		//장바구니 구분
		Long gubun = 1L;
		int result = as.apply(lecId, userid, gubun);
		return result;
	}
	
	//수강신청 목록 선택 --> 장바구니/전체강의
	@GetMapping(value = "applySelect")
	public String applySelect(String userid, Model model) {
		Member member = gm.getMember();
		model.addAttribute("member", member);
		
		String year = getYear();
		String semester = getSemester();
		model.addAttribute("userid", userid);
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		return "student/applySelect";
	}
	
	
	//전체 수강 년도 추출
	public List<String> yearList(String userid){
		List<ApplicationLec> yearListAll = as.yearList(userid);
		List<String> newList = new ArrayList<String>();
		for(int i=0; i<yearListAll.size(); i++) {
			newList.add(yearListAll.get(i).getLecture().getYear());  
		}
		List<String> yearList = newList.stream().distinct().collect(Collectors.toList());
		return yearList;
	}
	
	//선택에따른 수강신청 목록 조회
	@GetMapping(value = "applyForm")
	public String applyForm( String userid , String lecName, String page , Model model, 			
								@PageableDefault(size = 10,sort = "id", direction = Sort.Direction.DESC ) @Qualifier("lecture") Pageable pageable,								
			 					@PageableDefault(size = 10, sort = "member.userid", direction = Sort.Direction.DESC) @Qualifier("applicationLec") Pageable pageable2,
								@RequestParam("select") String select) {	
		
		Member member = gm.getMember();
		model.addAttribute("member", member);
		String year = getYear();
		String semester = getSemester();
		
		//List<Lecture> list = as.lectureListAll();
		if(lecName.isEmpty()) {
			lecName = "empty";
		}
		
		//페이징
		
		Page<Lecture> lectureList = as.lectureList(year,semester,pageable); //전체강의목록
		Page<Lecture> lectureSearch = as.findByName(year,semester,lecName,pageable); //강의명으로 검색한 목록 
		Page<ApplicationLec> applicationLecList = as.likeListPage(userid, year, semester, pageable2); //장바구니목록
		
		System.out.println("----------------------------------------------------------------------");
				
		if(select.equals("all") ) {	 //신청할 년도,학기의 전체 개설 강의 목록		
			int pageNum = lectureList.getPageable().getPageNumber(); //현재페이지
			System.out.println("applyForm pageNum->"+pageNum);
			int totalPage = lectureList.getTotalPages();//총페이지수
			int pageBlock = 5; //블럭의 수
			int startBlockPage = ((pageNum)/pageBlock)*pageBlock+1; 		
			int endBlockPage = startBlockPage+pageBlock-1;
			endBlockPage= totalPage<endBlockPage? totalPage:endBlockPage;
			model.addAttribute("startBlockPage", startBlockPage);
			model.addAttribute("endBlockPage", endBlockPage);
			model.addAttribute("lectureList", lectureList);	
		}else if (!lecName.equals("empty")) {
			int pageNum = lectureSearch.getPageable().getPageNumber(); //현재페이지
			int totalPage = lectureSearch.getTotalPages();//총페이지수
			int pageBlock = 5; //블럭의 수
			int startBlockPage = ((pageNum)/pageBlock)*pageBlock+1; 		
			int endBlockPage = startBlockPage+pageBlock-1;
			endBlockPage= totalPage<endBlockPage? totalPage:endBlockPage;
			model.addAttribute("startBlockPage", startBlockPage);
			model.addAttribute("endBlockPage", endBlockPage);
			model.addAttribute("lectureList", lectureSearch);	
			select = "all";
		}else {						 //신청할 년도,학기의 장바구니 강의 목록
			int pageNum = applicationLecList.getPageable().getPageNumber(); //현재페이지
			int totalPage = applicationLecList.getTotalPages();//총페이지수
			int pageBlock = 5; //블럭의 수
			int startBlockPage = ((pageNum)/pageBlock)*pageBlock+1; 		
			int endBlockPage = startBlockPage+pageBlock-1;
			endBlockPage= totalPage<endBlockPage? totalPage:endBlockPage;
			model.addAttribute("startBlockPage", startBlockPage);
			model.addAttribute("endBlockPage", endBlockPage);
			model.addAttribute("lectureList", applicationLecList);	
		
		}
		//수강신청 된 목록
		List<ApplicationLec> applyList = as.applyList(userid, year, semester);
		
		//총 신청학점

		int totalUnit =  totalUnit(applyList);

		model.addAttribute("list", applyList);
		model.addAttribute("userid", userid);
		model.addAttribute("select", select);
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		model.addAttribute("unit", totalUnit);
		return "student/applyForm";
	}
	


	//수강신청
	@ResponseBody
	@GetMapping(value = "apply")
	public int apply(Long lecId, String userid, Model model) {
		System.out.println("Applycontroller apply start...");
		//수강신청 구분
		Long gubun = 2L;
		int result = as.apply(lecId, userid, gubun);
		System.out.println("수강신청 결과------->"+result);
		return result;
	}
	

	//장바구니, 수강신청 기간 등록 폼
	@GetMapping(value = "registerTimeForm")
	public String registerTimeForm(Model model){
		Member member = gm.getMember();
		model.addAttribute("member", member);
		String year = getYear();
		String semester = getSemester();
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		return "student/registerTimeForm";
	}

	//기간 등록
	@GetMapping(value = "registerTime")
	public String registerTime(ApplyTime applyTime) { //@ModelAttribute 생략
		
		int result = as.register(applyTime);
	
		return "student/registerTime";
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
	
	//총 신청학점 계산
	private int totalUnit(List<ApplicationLec> applyList) {
		int count = 0;
		for(int i=0; i<applyList.size(); i++) {
			count += applyList.get(i).getLecture().getUnitScore();
		}
		return count;
	}
	
	
	/////////////////////////////////////////////////////////학사관리 년도, 학기별 강의 리스트//////////////////////
	@GetMapping(value = "lectureListForm")
	public String lectureListForm(Model model) {
	
		String userid = gm.getMember().getUserid();
		String year = getYear();	
		String semester = getSemester();
		List<ApplicationLec> applyList = as.applyList(userid, year, semester);
		List<String> yearList = yearList(userid);		
		
		model.addAttribute("userid", userid);
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		model.addAttribute("list", applyList);
		model.addAttribute("yearList", yearList);
		
		Member member =gm.getMember();
		model.addAttribute("member", member);
		return "student/lectureListForm";
		}
		
		@GetMapping(value = "lectureList")
		public String lectureList(String userid, String semester, String year, Model model) {
		Member member = gm.getMember();
		model.addAttribute("member", member);
			
		List<ApplicationLec> applyList = as.applyList(userid, year, semester);
		List<String> yearList = yearList(userid);
		
		model.addAttribute("userid", userid);
		model.addAttribute("year", year);
		model.addAttribute("semester", semester);
		model.addAttribute("list", applyList);
		model.addAttribute("yearList", yearList);
		
		return "student/lectureList";
	}	

	//과제 파일 업로드 form
	@RequestMapping("fileInsertForm")
	public String fileInsertForm(HttpServletRequest request, String userid, Long lecId, Model model) {
		Member member = gm.getMember();
		model.addAttribute("member", member);
		String referer = request.getHeader("Referer");
		
		model.addAttribute("userid", userid);
		model.addAttribute("lecId", lecId);
		model.addAttribute("referer", referer);
		return "student/fileInsert";
	}
	
	//과제 파일 업로드
	@RequestMapping("fileInsert" )
	public String fileInsert(HttpServletRequest request, @RequestPart MultipartFile file, String userid, Long lecId, String referer, Model model) throws Exception{
		Member member = gm.getMember();
		model.addAttribute("member", member);
		Report report = new Report();
		String fileRealName = file.getOriginalFilename(); //파일명
		Long size = file.getSize(); //파일 사이즈
		String fileExtension = fileRealName.substring(fileRealName.lastIndexOf("."),fileRealName.length());//확장자
		
		UUID uuid = UUID.randomUUID();
		String[] uuids = uuid.toString().split("-");
		String uniqueName = uuids[0]; //고유 문자열
		
		/* 절대경로 구하기
		 * 
		 * String fileExtension = fileRealName.substring(fileRealName.lastIndexOf("."),fileRealName.length()); //확장자명 구하기 
		 * String uploadFolder = "C:\\log"; String filePath =
		 * uploadFolder+"\\"+uniqueName+fileExtension; //절대 경로
		 */		
		
		//상대 경로 지정
		String path =  request.getSession().getServletContext().getRealPath("/upload/report"); 
		System.out.println("--------------------과제 upload path---------------------------"+path);		
		File savePath = new File(path); //realPath 경로
		if(!savePath.exists()) { //realPath 경로에 파일 업로드 하기 위한 폴더가 없으면 생성
			savePath.mkdirs();
		}
		
		path += File.separator + uniqueName + fileExtension; // 상대경로 + 구분자 + uuid + 확장자
		File saveFile = new File(path);
		
		try {
			file.transferTo(saveFile); //파일 저장
			report.setFilePath(path);
			report.setFileName(fileRealName);
			ApplicationLec applicationLec = as.findByIdName(userid,lecId);
			report.setApplicationLec(applicationLec);
			as.saveReport(report);
			
			
		} catch (Exception e) {
			System.out.println("파일 업로드 에러---->"+e.getMessage());
		}

		
	    return "redirect:"+ referer;
		
			
	}
	
	//main
	@GetMapping(value = "studentMain")
	public String studentMain(Model model) {
		Member member = gm.getMember();
		model.addAttribute("member", member);
		
		String userid = gm.getMember().getUserid();
		String year = getYear();
		String semester = getSemester();
		List<ApplicationLec> list = as.applyList(userid, year, semester);
		
		//오늘 요일 
		LocalDate now = LocalDate.now();
		String today = now.getDayOfWeek().getDisplayName(TextStyle.NARROW, Locale.KOREAN);
		
		//시간표 - 요일 리스트
		List<String> day = new ArrayList<String>();
		day.add("월");day.add("화");day.add("수");day.add("목");day.add("금");
		
		
		model.addAttribute("list", list);
		model.addAttribute("today", today);
		model.addAttribute("day", day);
		return "student/main";
	}
	
	//수강신청
		@GetMapping(value = "timetable")
		public String timetable(Model model) {
			Member member = gm.getMember();
			model.addAttribute("member", member);
			
			String userid = gm.getMember().getUserid();
			String year = getYear();
			String semester = getSemester();
			List<ApplicationLec> list = as.applyList(userid, year, semester);
			
			//오늘 요일 
			LocalDate now = LocalDate.now();
			String today = now.getDayOfWeek().getDisplayName(TextStyle.NARROW, Locale.KOREAN);
			
			//시간표 - 요일 리스트
			List<String> day = new ArrayList<String>();
			day.add("월");day.add("화");day.add("수");day.add("목");day.add("금");
			
			
			model.addAttribute("list", list);
			model.addAttribute("today", today);
			model.addAttribute("day", day);
			return "student/timetable";
		}

	
	
	
}
