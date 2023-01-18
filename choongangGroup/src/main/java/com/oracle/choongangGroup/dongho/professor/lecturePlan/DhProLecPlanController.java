package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanLecDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanWeekDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.PlanPdfDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.ShowPlanDetailDto;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/professor")
public class DhProLecPlanController {
	private final GetMember getMember;
	private final DhProLecPlanService dhProLecPlanService;
	
	//강의페이지 요청
	@GetMapping("/lecPlanPage")
	public String lecPlanPage(Model model) {
		log.info("===lecPlanPage Start===");
		Member member = getMember.getMember();
		model.addAttribute("member", member);
		return "/professor/lecPlan";
	}
	
	//강의리스트
	@ResponseBody
	@PostMapping("/lecList")
	public List<LecPlanLecDto> lecPlanlecList(String year, 
											  String semester, 
											  String profName) {
		log.info("===lecPlanlecList Start===");
		String lecStatus = "0"; // 개설된 강의 상태
		
		return dhProLecPlanService.findByProfNameAndYearAndSemester(profName, year, semester, lecStatus);
	}
	
	//강의계획서 세부내용
	@ResponseBody
	@PostMapping("/showPlanDetail")
	public ShowPlanDetailDto showPlanDetail(Long lecId) {
		log.info("===showPlanDetail Start===");
		LecPlanDto        lec_plan      = dhProLecPlanService.findLecPlanByLecId(lecId);
		List<LecPlanWeekDto>    lec_plan_weekList = dhProLecPlanService.findLecPlanWeekByLecId(lecId);
		ShowPlanDetailDto showPlanDetailDto = new ShowPlanDetailDto();
		showPlanDetailDto.setLec_plan(lec_plan);
		showPlanDetailDto.setLec_plan_weekList(lec_plan_weekList);
		return showPlanDetailDto;
	}
	
	//강의계획서 입력
	@ResponseBody
	@PostMapping("/insertOrUpdatePlan")
		public int insertPlan(LecPlanDto lecPlanDto) {
		log.info("===insertPlan Start===");
		int resultInsertPlan = 0;
		int resultInsertWeek = 0;
		int resultUpdatePlan = 0;
		int resultUpdateWeek = 0;
		int InsertResult = 0;
		int UpdateResult = 0;
		Optional<LecPlanDto> optionalLP = dhProLecPlanService.findByLecIdWithOptional(lecPlanDto.getLec_id());
		log.info("isPresent LecPlan : {}",optionalLP.isPresent());
		if (optionalLP.isPresent()) {
			resultUpdatePlan = dhProLecPlanService.updatePlan(lecPlanDto);
			resultUpdateWeek = dhProLecPlanService.updateWeek(lecPlanDto.getPlanWeekArray());
			if(resultUpdatePlan > 0 && resultUpdateWeek != 0) {
				UpdateResult = 1;
			} else {
				UpdateResult = 0;
			}
			
			return UpdateResult;
		} else {
			resultInsertPlan = dhProLecPlanService.insertPlan(lecPlanDto);
			resultInsertWeek = (int) dhProLecPlanService.insertWeek(lecPlanDto.getPlanWeekArray());
			if(resultInsertPlan > 0 && resultInsertWeek > 0) {
				InsertResult = 1;
			} else {
				InsertResult = 0;
			}
			return InsertResult;
		}
	}
	
	//강의계획서 삭제
	@ResponseBody
	@PostMapping("/deletePlan")
	public int deletePlan(@RequestParam("lec_id") Long lec_id) {
		log.info("===deletePlan Start===");
		int result = dhProLecPlanService.deletePlanAndLec(lec_id);
		return result;
	}
	
	//강의계획서 pdf 생성
	@ResponseBody
	@PostMapping(value = "/createPdf", produces = MediaType.TEXT_PLAIN_VALUE)
	public String createPdf(PlanPdfDto planPdfDto, HttpServletRequest request) throws Exception {
		log.info("===createPdf Start===");
		String pdfStr = dhProLecPlanService.generatePdf(planPdfDto, request);
		return pdfStr;
	}
	
	//강의계획서 파일 업로드
	@ResponseBody
	@PostMapping("/uploadPlanFile")
	public int uploadPlanFile(@RequestPart(value = "data") String lec_id, @RequestPart(value = "uploadFile") MultipartFile[] multipartFiles) {
		log.info("===uploadPlanFile Start===");
		int result = 0;
		result = dhProLecPlanService.uploadPlanFile(lec_id, multipartFiles);
		return result;
	}
}
