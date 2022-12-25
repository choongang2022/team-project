package com.oracle.choongangGroup.changhun.evaluation;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/manager")
public class EvaController {
	
	private final EvaService es;
	private final GetMember getMember;
	
	@RequestMapping("/EvaManagementForm")
	public String EvaManagementForm(Model model,
									@RequestParam(value = "pname", defaultValue = "오태우") String pname) {
		
		log.info("EvaManagementForm pname --> {}",pname);
		List<EvaVo> evaList = es.evaList(pname);
		List<EvaVo> reviewList = es.reviewList(pname);
		EvaVo total = es.total(pname);
		Member member = getMember.getMember();
		
		model.addAttribute("member", member);
		model.addAttribute("evaList", evaList);
		model.addAttribute("reviewList", reviewList);
		model.addAttribute("total", total);
		
		return "manager/EvaManagementForm";
	}
	
	@ResponseBody
	@RequestMapping("/findProf")
	public List<String> findProf(){
		
		List<String> profList = es.profList();
		
		return profList;
		
	}
	
	
}
