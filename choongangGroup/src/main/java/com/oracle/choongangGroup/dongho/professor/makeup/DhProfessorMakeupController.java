package com.oracle.choongangGroup.dongho.professor.makeup;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAdjuster;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.authutils.GetMember;
import com.oracle.choongangGroup.hs.lecManagement.LectureVO;
import com.oracle.choongangGroup.sh.domain.Lecture;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/professor")
public class DhProfessorMakeupController {
	private final GetMember getMember;
	private final DhProfessorMakeupSerivce dhProfessorMakeupSerivce;
	
	// 휴보강 신청 페이지 요청
	@GetMapping("/makeupPage")
	public String makeupPage(Model model) {
		Member member = getMember.getMember();
		model.addAttribute("member", member);
		// select에 표시할 강의 목록 조회
		log.info("select 출력 강의 list 조회 시작");
		String profName = getMember.getMember().getName();
		log.info(profName);
		String lecStatus = "0"; // 개설 승인된 상태 0
		List<LectureVO> lectureVOList = dhProfessorMakeupSerivce.findByProfAndStatus(profName, lecStatus);
		for (LectureVO lectureVO : lectureVOList) {
			log.info(lectureVO.getProf_name());
		}
		model.addAttribute("lectureVOList", lectureVOList);
		return "/professor/makeup";
	}
	
	@ResponseBody
	@PostMapping("/getOrderList")
	public List<OrdersDto> getOrderList(Long id) {
		log.info("===OrderList 조회 시작===");
		List<OrdersDto> orderDtoList = dhProfessorMakeupSerivce.findByLecId(id);
		return orderDtoList;
	}
	
	@ResponseBody
	@PostMapping("/showOrderDetail")
	public OrdersDto showOrderDetail(Long lecOrdersId) {
		log.info("===OrderDetail 조회 시작===");
		OrdersDto orderDto = dhProfessorMakeupSerivce.findByLec_orders_id(lecOrdersId);
		return orderDto;
	}
	
	@ResponseBody
	@PostMapping("/updateOrders")
	public int updateOrders(@RequestBody OrdersDto ordersDto) {
		log.info("===휴보강 정보 update 시작===");
		int result = 0;
		log.info(ordersDto.getLec_orders_id().toString());
		log.info(ordersDto.getLec_order_reason());
		
		result = dhProfessorMakeupSerivce.updateOrders(ordersDto);
		log.info(Integer.toString(result));
		return result;
	}
	
	
}
