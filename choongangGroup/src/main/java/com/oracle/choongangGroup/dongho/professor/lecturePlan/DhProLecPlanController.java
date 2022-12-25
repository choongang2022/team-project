package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;
import java.util.Optional;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/professor")
public class DhProLecPlanController {
	private final GetMember getMember;
	private final DhProLecPlanService dhProLecPlanService;
	
	@GetMapping("/lecPlanPage")
	public String lecPlanPage(Model model) {
		Member member = getMember.getMember();
		System.out.println(member);
		model.addAttribute("member", member);
		return "/professor/lecPlan";
	}
	
	@ResponseBody
	@PostMapping("/lecList")
	public List<LecPlanLecDto> lecPlanlecList(String year, 
											  String semester, 
											  String profName) {
		String lecStatus = "0"; // 개설된 강의 상태
		
		return dhProLecPlanService.findByProfNameAndYearAndSemester(profName, year, semester, lecStatus);
	}
	
	@ResponseBody
	@PostMapping("/showPlanDetail")
	public ShowPlanDetailDto showPlanDetail(Long lecId) {
		log.info(lecId.toString());
		LecPlanDto        lec_plan      = dhProLecPlanService.findLecPlanByLecId(lecId);
		List<LecPlanWeekDto>    lec_plan_weekList = dhProLecPlanService.findLecPlanWeekByLecId(lecId);
		ShowPlanDetailDto showPlanDetailDto = new ShowPlanDetailDto();
		showPlanDetailDto.setLec_plan(lec_plan);
		showPlanDetailDto.setLec_plan_weekList(lec_plan_weekList);
		return showPlanDetailDto;
	}
	
	@ResponseBody
	@PostMapping("/insertOrUpdatePlan")
		public int insertPlan(LecPlanDto lecPlanDto) {
		System.out.println(lecPlanDto.toString());
		int resultInsertPlan = 0;
		int resultInsertWeek = 0;
		int resultUpdatePlan = 0;
		int resultUpdateWeek = 0;
		int InsertResult = 0;
		int UpdateResult = 0;
		Optional<LecPlanDto> optionalLP = dhProLecPlanService.findByLecIdWithOptional(lecPlanDto.getLec_id());
		System.out.println(optionalLP.isPresent());
		if (optionalLP.isPresent()) {
			resultUpdatePlan = dhProLecPlanService.updatePlan(lecPlanDto);
			resultUpdateWeek = dhProLecPlanService.updateWeek(lecPlanDto.getPlanWeekArray());
			if(resultUpdatePlan > 0 && resultUpdateWeek != 0) {
				UpdateResult = 1;
			} else {
				UpdateResult = 0;
			}
			System.out.println(resultUpdatePlan);
			System.out.println(resultUpdateWeek);
			
			return UpdateResult;
		} else {
			resultInsertPlan = dhProLecPlanService.insertPlan(lecPlanDto);
			resultInsertWeek = (int) dhProLecPlanService.insertWeek(lecPlanDto.getPlanWeekArray());
			if(resultInsertPlan > 0 && resultInsertWeek > 0) {
				InsertResult = 1;
			} else {
				InsertResult = 0;
			}
			System.out.println(resultInsertPlan);
			System.out.println(resultInsertWeek);
			return InsertResult;
		}
	}
	
	@ResponseBody
	@PostMapping("/deletePlan")
	public int deletePlan(@RequestParam("lec_id") Long lec_id) {
		int result = 0;
		System.out.println(lec_id);
		result = dhProLecPlanService.deletePlanAndLec(lec_id);
		
		return result;
		
	}
	
}
