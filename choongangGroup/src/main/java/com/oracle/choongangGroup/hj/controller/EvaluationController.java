package com.oracle.choongangGroup.hj.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.hj.model.EvaluationVo;
import com.oracle.choongangGroup.hj.model.MemberVo;
import com.oracle.choongangGroup.hj.service.EvaluationService;

import lombok.RequiredArgsConstructor;


@RequestMapping("/student/")
@RequiredArgsConstructor
@Controller
public class EvaluationController {

	private final EvaluationService es;
	private final GetMember gm;


	// 강의평가  화면 (학생)
	@RequestMapping(value = "evaluationList")
	public String listevaluation( Model model) {

		System.out.println("EvaluationController listevaluation start. . .  . . ");
		//System.out.println("userid------------------->" + userid);
		// System.out.println("cd--------------->" + cd);

		String userid = gm.getMember().getUserid();
		
		//이름받기 
		MemberVo memberinfo = es.infoList(userid);
		
		// 셀렉트바 강의명 +교수이름
		List<EvaluationVo> evList = es.findev(userid);
		model.addAttribute("evList", evList);

		// 강의평가항목 카테고리
		List<EvaluationVo> cgList = es.findcg(userid);
		model.addAttribute("cgList", cgList);
		model.addAttribute("userid", userid);
		model.addAttribute("member",memberinfo);
		return "student/evaluationList";

	}

//	// 강의평가 내용만 조회 (수정페이지) (관리자용)
//	@RequestMapping(value = "updateFormEvaluation")
//	public String EvaluationList( Model model, HttpServletRequest request) {
//		System.out.println("EvaluationController EvaluationList start. . .  . . ");
//
//		String userid = gm.getMember().getUserid();
//		
//		
//		List<EvaluationVo> cgList2 = es.findcg2(userid);
//		model.addAttribute("cgList2", cgList2);
//		model.addAttribute("userid", userid);
//
//		return "student/updateFormEvaluation";
//
//	}
//
//	// 강의평가 내용 수정(관리자용)
//	@ResponseBody
//	@GetMapping(value = "realupdateEvaluation")
//	public String updateEvaluation(HttpServletRequest request, Model model) throws Exception {
//
//		System.out.println("강의평가 수정 하는곳  start. . .  . . ");
//
//		String userid = gm.getMember().getUserid();
//		
//		// string 으로 변환된 rs 값 넘어온다.
//		System.out.println("param--->" + request.getParameter("rsList"));
//
//		String rs = request.getParameter("rsList");
//      
//		// json타입 배열로 변환
//		JsonArray jArray = new Gson().fromJson(rs, JsonArray.class);
//		
//		//sql insert용 리스트
//		ArrayList<EvaluationVo> rsList = new ArrayList<EvaluationVo>();
//
//		for (int i = 0; i < jArray.size(); i++) {
//
//			EvaluationVo vo = new EvaluationVo();
//
//			JsonElement jObj = jArray.get(i);// 첫번째 줄 잘라옴
//			JsonArray jsonArray = jObj.getAsJsonArray(); // 첫번째 줄값 나온걸 다시 배열로 바꿔줌.
//
//			System.out.println("두번째자름 ---> " + jsonArray.get(0)); // 대분류
//			System.out.println("두번째자름 ---> " + jsonArray.get(1)); // 소분류
//			System.out.println("두번째자름 ---> " + jsonArray.get(2)); // 질문내용
//			
//			vo.setBig_category(jsonArray.get(0).toString().replace("\"","")); //String 타입으로 변환
//			vo.setSmall_category(jsonArray.get(1).toString().replace("\"",""));
//			vo.setCategory_content(jsonArray.get(2).toString().replace("\"",""));
//			
//			rsList.add(vo);
//			
//		}
//		
//		//학적 수정한것  update 
//		int updateCount = es.updateEv(rsList);
//		model.addAttribute("uptcnt", updateCount);	
//		
//		// 데이터 넘길시 
//		// Gson 사용 데이터 전송 (리스트 ->json 타입으로 변경)
////		Gson gson = new Gson();
////		String jsonRs = gson.toJson(rsList);
//		
//		return "student/updateFormEvaluation";
//
//	}

 

//	 강의평가 insert
//	@ResponseBody
	@PostMapping(value = "saveEvaluation")
	public String saveEvaluation(EvaluationVo evaluation, Model model) {
		System.out.println("EvaluationController saveEvaluation start. . .  . . ");

		String userid = gm.getMember().getUserid();
		int result = 0;

		// 빅,스몰 카테고리짤라주기
		String[] big = evaluation.getBig_category().split(",");
		String[] small = evaluation.getSmall_category().split(",");

		// 빅,스몰 카테고리짤라준값 보기
		  for( int i =0 ; i <big.length ; i++) {
			  System.out.println( "짜름 ********** getBig_category-->"+big[i]);
			  System.out.println( "짜름 ********** getSmall_category-->"+small[i]);
		  }
		  

		// 점수 list에 담아줌
		List<Long> scoreList1 = new ArrayList<Long>();
		scoreList1.add(evaluation.getScore1());
		scoreList1.add(evaluation.getScore2());
		scoreList1.add(evaluation.getScore3());
		scoreList1.add(evaluation.getScore4());
		scoreList1.add(evaluation.getScore5());
		scoreList1.add(evaluation.getScore6());

		System.out.println("scoreList1------***********************>" + scoreList1);

		// 배열만들어서 체크한 값 한번에 넣어줌
		List<EvaluationVo> scoreList = new ArrayList<EvaluationVo>();

		EvaluationVo ev = null;

		for (int i = 0; i < big.length; i++) {

			ev = new EvaluationVo();

			ev.setBig_category(big[i]);
			ev.setSmall_category(small[i]);
			ev.setLec_id(evaluation.getLec_id());
			ev.setUserid(evaluation.getUserid());
			ev.setReview(evaluation.getReview());
			ev.setScoreList1(scoreList1.get(i));

			scoreList.add(ev);

		}

		System.out.println("scoreList----***************>" + scoreList);

		result = es.insertscore(scoreList);
 
		return "redirect:evaluationList";
   

	}


}
