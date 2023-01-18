package com.oracle.choongangGroup.changhun.evaluation;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.hj.model.EvaluationVo;
import com.oracle.choongangGroup.hj.service.EvaluationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/manager")
public class EvaController {
	
	/////현지 수정
	private final EvaluationService hjes;
	
	
	private final EvaService es;
	private final GetMember getMember;
	private final EvaDao repository;
	
	@RequestMapping("/EvaManagementForm")
	public String EvaManagementForm(Model model,
									@RequestParam(value = "lecId", defaultValue = "1") String lecid,
									@RequestParam(value = "pname", required = false) String pname) {
		
		log.info("EvaManagementForm pname --> {}",lecid);
		List<EvaVo> evaList = es.evaList(lecid);
		List<EvaVo> reviewList = es.reviewList(lecid);
		List<String> profList = repository.profNameList();
		EvaVo total = es.total(lecid);
		Member member = getMember.getMember();
		
		
		model.addAttribute("member", member);
		model.addAttribute("profList", profList);
		model.addAttribute("evaList", evaList);
		model.addAttribute("reviewList", reviewList);
		model.addAttribute("total", total);
		
		return "manager/EvaManagementForm";
	}
	
	@ResponseBody
	@RequestMapping("/findProf")
	public List<EvaVo> findProf(@RequestParam(value = "pname", defaultValue = "유상신") String pname){
		
		List<EvaVo> profList = es.profList(pname);
		
		log.info("findProf size ==> {}",profList.size() );
		
		return profList;
		
	}
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	//////////////////////////////현지 강의평가 수정/////////////////////////////////////////////////////////////////////////////
	
	
	// 강의평가 내용만 조회 (수정페이지) (관리자용)
	@RequestMapping(value = "updateFormEvaluation")
	public String EvaluationList( Model model, HttpServletRequest request) {
		System.out.println("EvaluationController EvaluationList start. . .  . . ");

		String userid = getMember.getMember().getUserid();
		Member member = getMember.getMember();
		
		List<EvaluationVo> cgList2 = hjes.findcg2(userid);
		model.addAttribute("cgList2", cgList2);
		model.addAttribute("userid", userid);
		model.addAttribute("member", member);


		return "manager/updateFormEvaluation";

	}

	// 강의평가 내용 수정(관리자용)
	@ResponseBody
	@GetMapping(value = "realupdateEvaluation")
	public String updateEvaluation(HttpServletRequest request, Model model) throws Exception {

		System.out.println("강의평가 수정 하는곳  start. . .  . . ");

		String userid = getMember.getMember().getUserid();
		Member member = getMember.getMember();
		// string 으로 변환된 rs 값 넘어온다.
		System.out.println("param--->" + request.getParameter("rsList"));

		String rs = request.getParameter("rsList");
      
		// json타입 배열로 변환
		JsonArray jArray = new Gson().fromJson(rs, JsonArray.class);
		
		//sql insert용 리스트
		ArrayList<EvaluationVo> rsList = new ArrayList<EvaluationVo>();

		for (int i = 0; i < jArray.size(); i++) {

			EvaluationVo vo = new EvaluationVo();

			JsonElement jObj = jArray.get(i);// 첫번째 줄 잘라옴
			JsonArray jsonArray = jObj.getAsJsonArray(); // 첫번째 줄값 나온걸 다시 배열로 바꿔줌.

			System.out.println("두번째자름 ---> " + jsonArray.get(0)); // 대분류
			System.out.println("두번째자름 ---> " + jsonArray.get(1)); // 소분류
			System.out.println("두번째자름 ---> " + jsonArray.get(2)); // 질문내용
			
			vo.setBig_category(jsonArray.get(0).toString().replace("\"","")); //String 타입으로 변환
			vo.setSmall_category(jsonArray.get(1).toString().replace("\"",""));
			vo.setCategory_content(jsonArray.get(2).toString().replace("\"",""));
			
			rsList.add(vo);
			
		}
		
		//학적 수정한것  update 
		int updateCount = hjes.updateEv(rsList);
		model.addAttribute("uptcnt", updateCount);
		model.addAttribute("member", member);

		
		return "manager/updateFormEvaluation";

	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	
}
