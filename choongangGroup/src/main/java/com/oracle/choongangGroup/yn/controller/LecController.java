package com.oracle.choongangGroup.yn.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.hs.approval.ApprovalService;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Grade;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.yn.repository.GradeRepository;
import com.oracle.choongangGroup.yn.repository.LecRepository;
import com.oracle.choongangGroup.yn.repository.LecRepositoryImpl;
import com.oracle.choongangGroup.yn.service.GradeServiceImpl;
import com.oracle.choongangGroup.yn.service.LecService;
import com.oracle.choongangGroup.yn.service.LecServiceImpl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
//@RequestMapping("/professor")
public class LecController {
	private final LecService ls;
	private final LecServiceImpl lsi;
	private final LecRepository lr;
	private final GradeRepository gr;
	private final GradeServiceImpl gs;
	private final ApprovalService as;
	
	private final LecRepositoryImpl lm;
	private final GetMember gm;

	
	// 캘린더이동 ---> 작업중 : 일단 연결만
//	@GetMapping(value = "professor/calenderForm") public String lecList(Model model) { //
//	String name = gm.getMember().getName();
//	String userid = gm.getMember().getUserid();
//	System.out.println(name);
//	return "/professor/calenderForm"; }

	
	////// 강의개설 페이지 시작 //////
	// 교수의 강의리스트 조회 - 로그인된 교수이름으로 강의조회
	@GetMapping(value = "professor/lecCreateList")
	public String findLecList(Model model) {

		// 접속아이디 -> 교수 이름 찾기
		String name = gm.getMember().getName();
		System.out.println(name);

		///////// 접속 아이디 받아서 넘기기////////////
		List<Lecture> lectureList = lr.findByProfOrderByIdAsc(name);
		System.out.println("lectureList.size() --> " + lectureList.size());
		model.addAttribute("lecCnt", lectureList.size());
		model.addAttribute("lecList", lectureList);
		model.addAttribute("member", gm.getMember());
		
		return "professor/lecCreateList";
	}

	// 강의 한건 조회 -> 업데이트시 사용
	@GetMapping(value = "professor/lecFindById")
	@ResponseBody
	public Lecture findLec(@RequestParam(value = "id") Long id, Model model) {

		Lecture lecture = lr.findById(id);
		log.info("lec id == {}", lecture.getId());
		return lecture;
	}

	// 강의 저장 + 이수구분코드 input -> 이수구분 text 컬럼 추가.
	@PostMapping(value = "professor/lecSave")
	public String saveLec(Lecture lecture, Model model) {
		// 접속이름
		String name = gm.getMember().getName();

		log.info("LecController saveLec START ====================");
		System.out.println("lecture name ====> " + lecture.getName());

		lecture.setProf(name);
		switch (lecture.getTypeCode()) {
		case "M":
			lecture.setType("전필");
			break;
		case "S":
			lecture.setType("전선");
			break;
		case "C":
			lecture.setType("교양");
			break;

		default:
			break;
		}
		// 강의테이블에 저장
		lr.save(lecture);

		return "redirect:/professor/lecCreateList";
	}

	// 강의 저장 + 이수구분코드 input -> 이수구분 text 컬럼 추가.
	@PostMapping(value = "professor/lecSearch")
	@ResponseBody
	public List<Lecture> searchLec(/* HttpSession session, */ Lecture lecture, Model model) {
		// 접속이름
		/* String name = (String) session.getAttribute("name"); */
		String name = gm.getMember().getName();

		log.info("LecController searchLec START ====================");
		log.info("YEAR ==================== {}", lecture.getYear());
		log.info("getSemester ==================== {}", lecture.getSemester());
		log.info("getName ==================== {}", lecture.getName());

		if (lecture.getTypeCode() != null && !"".equals(lecture.getTypeCode())) {
			lecture.setTypeCode(lecture.getTypeCode().substring(0, lecture.getTypeCode().length() - 1));
		}

		List<Lecture> serchList = lm.searchLec(lecture, name);
		System.out.println("serchList -->" + serchList.size());
		model.addAttribute("lecCnt", serchList.size());

		log.info("serchList ==================== {}", serchList);

		return serchList;
	}

	// 강의 삭제
	@GetMapping(value = "professor/lecDelete")
	public String deleteLec(@RequestParam(value = "id") Long id, Model model) {
		log.info("LecController deleteLec START ====================");
		log.info("LecController id = {}", id);

		lr.deleteById(id);

		return "redirect:/professor/lecCreateList";
	}

	/*
	 * 강의관리 메인 1. 로그인된 교수의 강의조회 2. 강의를 듣는 Member(학생) 조회 .(findByLecture_IdAndGubun)
	 */
	@GetMapping(value = "professor/lecMgMain")
	public String lecMgList(Model model) {
		// 접속아이디 -> 교수 이름 찾기
		String name = gm.getMember().getName();
		System.out.println(name);

		///////// 접속교수 이름 받아서 넘기기 - 교수의 개강된 강의 조회 ////////////
		List<Lecture> lectureList = lr.findByProfAndStatusOrderByIdAsc(name, "0");
		
		List<Map<String, Object>> mapList = new ArrayList<Map<String,Object>>();
		for(Lecture lecList : lectureList) {
			Map<String, Object> map = new HashMap<String, Object>();
			map.put("lecture", lecList);
			List<ApplicationLec> alList = ls.findByLecture_IdAndGubun(lecList.getId(), 2L);
			map.put("memberCnt", alList.size());
			mapList.add(map);
		}
		
		System.out.println(lectureList.size());
		model.addAttribute("lecCnt", lectureList.size());
		
		model.addAttribute("lecList", mapList);
		model.addAttribute("member", gm.getMember());
		
		return "professor/lecMgMain";
	}

	/*
	 * 출석관리 1. 교수의 강의 한건 조회.(findById) 2. 강의를 듣는 Member(학생) 조회
	 * .(findByLecture_IdAndGubun)
	 */
	@GetMapping(value = "professor/lecAttendanceCheck")
	public String selectOneLec(@RequestParam(value = "id") Long id, Model model) {
		String name = gm.getMember().getName();
		Lecture lecture = lr.findById(id);
		Long gubun = (long) 2;
		
		List<ApplicationLec> alList = ls.findByLecture_IdAndGubun(id, gubun);
		List<Lecture> lectureList = lr.findByProfAndStatusOrderByIdAsc(name, "0"); // 개설된 강의조회
		List<Member> memList = new ArrayList<Member>();
		
		System.out.println(lectureList.size());
		for (ApplicationLec applicationLec : alList) {
			memList.add(applicationLec.getMember());
		}
		// 출석부 정렬 : 이름순 - 학년순 - 학번순
		Collections.sort(memList, new Comparator<Member>() {
			@Override
			public int compare(Member o1, Member o2) {
				String name1 = o1.getName();
				String name2 = o2.getName();

				Long grade1 = o1.getGrade();
				Long grade2 = o2.getGrade();
				
				String userid1 = o1.getName();
				String userid2 = o2.getName();

				if (name1 == name2) {
					if(grade1 == grade2) {
						return userid1.compareTo(userid2);
					}
					return grade1.compareTo(grade2);
				}
				return name1.compareTo(name2); // 비교 리턴 -> -1, 0, 1
			}
		});

		model.addAttribute("lecList", lectureList);
		model.addAttribute("lecture", lecture);
		model.addAttribute("memList", memList);
		model.addAttribute("memCnt", memList.size());
		model.addAttribute("member", gm.getMember());

		return "professor/lecCheckForm";
	}

	/********* 출석부 다운 excel *******/
	@GetMapping("professor/lecAttendExcel")
	public ResponseEntity lecAttendExcel(@RequestParam(value = "id") Long id, HttpServletResponse response,
										 @RequestParam(value = "excelDownload") boolean excelDown) {
		System.out.println("lecAttendExcel" + response);
		return ResponseEntity.ok(lsi.getLecCheck(response, excelDown, id));
	}

	/*
	 * 성적관리 1. 강의 조회
	 */
	@GetMapping(value = "professor/lecScore")
	public String lecScore(Model model) {
		String name = gm.getMember().getName();
		List<Lecture> lecList = lr.findByProfAndStatusOrderByIdAsc(name, "0");

		model.addAttribute("lecList", lecList);
		model.addAttribute("lecCnt", lecList.size());
		model.addAttribute("member", gm.getMember());
		return "professor/lecScoreForm";
	}

	// 성적 : 강의 한건 조회 -> 업데이트시 사용
	@GetMapping(value = "professor/lecScoreForm")
	@ResponseBody
	public Map<String, Object> lecScoreForm(@RequestParam(value = "id") Long id, Model model) {
		Long gubun = (long) 2;
		List<ApplicationLec> alList = ls.findByLecture_IdAndGubun(id, gubun);
		Collections.sort(alList, new Comparator<ApplicationLec>() {

			@Override
			public int compare(ApplicationLec o1, ApplicationLec o2) {
				Long grade1 = o1.getMember().getGrade();
				Long grade2 = o2.getMember().getGrade();

				String userid1 = o1.getMember().getUserid();
				String userid2 = o2.getMember().getUserid();

				if (grade1 == grade2) {
					return userid1.compareTo(userid2);
				}
				return grade1.compareTo(grade2); // 비교 리턴 -> -1, 0, 1
			}
		});

		List<Member> memList = new ArrayList<Member>();
		List<Grade> grList = new ArrayList<Grade>();
		Map<String, Object> map = new HashMap<>();

		for (ApplicationLec applicationLec : alList) {
			memList.add(applicationLec.getMember());
			grList.add(gr.findByApplicationLec(applicationLec));
		}

		map.put("memList", memList);
		map.put("grList", grList);
		return map;
	}

	// 성적 : 점수저장
	@PostMapping(value = "professor/lecScoreSave")
	@ResponseBody
	public String lecScoreSave(@RequestParam(value = "data") String data, @RequestParam(value = "lecId") Long lecId,
								Model model) {

		JSONArray jarray = new JSONArray(data);

		List<Grade> gradeList = new ArrayList<>();

		int insertCnt = 0;
		for (int i = 0; i < jarray.length(); i++) {
			ApplicationLec applicationLec = new ApplicationLec();
			Member mem = new Member();
			Lecture lec = new Lecture();
			Grade grade = new Grade();

			lec.setId(lecId);
			mem.setUserid(jarray.getJSONObject(i).getString("userid"));

			applicationLec.setLecture(lec);
			applicationLec.setMember(mem);

			if (!"".equals(jarray.getJSONObject(i).getString("id"))) {
				grade.setId(jarray.getJSONObject(i).getLong("id"));
			}

			grade.setAttendance(jarray.getJSONObject(i).getLong("attendance"));
			grade.setFinals(jarray.getJSONObject(i).getLong("finals"));
			grade.setMidterm(jarray.getJSONObject(i).getLong("midterm"));
			grade.setReport(jarray.getJSONObject(i).getLong("report"));
			grade.setCredits(jarray.getJSONObject(i).getString("credits"));
			
			switch (jarray.getJSONObject(i).getString("credits")) {
			case "A+":
				grade.setTotal(4.5);
				break;
			case "A":
				grade.setTotal(4.0);
				break;
			case "B+":
				grade.setTotal(3.5);
				break;
			case "B":
				grade.setTotal(3.0);
				break;
			case "C+":
				grade.setTotal(2.5);
				break;
			case "C":
				grade.setTotal(2.0);
				break;
			case "D+":
				grade.setTotal(1.5);
				break;
			case "D":
				grade.setTotal(1.0);
				break;
			case "F":
				grade.setTotal(0.0);
				break;
			default:
				log.error("성적입력오류");
				break;
			}
			grade.setApplicationLec(applicationLec);
			gradeList.add(grade);
			insertCnt++;
		} // for end
		gr.saveAll(gradeList);

		return String.valueOf(insertCnt);
	}

	
	// 점수 다운 excel
	@GetMapping("professor/scoreExcelDown")
	public ResponseEntity lecScoreExcel(@RequestParam(value = "id") Long id, HttpServletResponse response) {
		System.out.println("lecAttendExcel" + response);
		return ResponseEntity.ok(gs.lecScoreExcel(response, id));
	}
	
	// 점수마감(마감버튼 클릭시 상태변경)
	@GetMapping("professor/lecScoreFinish")
	@ResponseBody
	public String lecScoreFinish(@RequestParam(value = "id") Long id, Model model) {
		Lecture lecture = lr.findById(id);
		lecture.setScoreStatus("1");
		lr.save(lecture);
		return "OK"; 
	}

}
